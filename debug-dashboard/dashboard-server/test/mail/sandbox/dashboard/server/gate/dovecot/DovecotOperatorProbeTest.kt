package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
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
                    "* 2 EXISTS\r\n" +
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
        assertSearchAllUidCountMatchesExists(response)
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
    fun fullMailboxReadAcceptsZeroCountsAfterExistsRecoversBeforeFetch() {
        val validLiteral =
            "Message-ID: <zero-counts@local.test>\r\n\r\n"
        val fixture = probeFixture(
            response = (
                successfulReadPrefixBeforeExamineState() +
                    "* 0 EXISTS\r\n" +
                    "* 0 RECENT\r\n" +
                    "* 1 EXISTS\r\n" +
                    "A003 OK [READ-ONLY] Examine completed\r\n" +
                    "* SEARCH 7\r\n" +
                    "A004 OK Search completed\r\n" +
                    "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${validLiteral.length}}\r\n" +
                    validLiteral +
                    ")\r\n" +
                    "A005 OK Fetch completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            secret = "zero-counts-secret",
            requireMailboxRead = true,
        )

        assertEquals(
            DovecotOperatorProbeResult.Success,
            fixture.probe.probe(TARGET, fixture.credential),
        )
        assertClosedAndWiped(fixture, "zero-counts-secret")
    }

    @Test
    fun fullMailboxReadRejectsFetchAfterExistsFallsToZero() {
        val validLiteral =
            "Message-ID: <empty-mailbox@local.test>\r\n\r\n"
        val fixture = probeFixture(
            response = (
                successfulReadPrefix() +
                    "* SEARCH 7\r\n" +
                    "A004 OK Search completed\r\n" +
                    "* 0 EXISTS\r\n" +
                    "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${validLiteral.length}}\r\n" +
                    validLiteral +
                    ")\r\n" +
                    "A005 OK Fetch completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            secret = "empty-mailbox-secret",
            requireMailboxRead = true,
        )

        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            fixture.probe.probe(TARGET, fixture.credential),
        )
        assertClosedAndWiped(fixture, "empty-mailbox-secret")
    }

    @Test
    fun fullMailboxReadRejectsFetchAfterLastMessageIsExpunged() {
        val validLiteral =
            "Message-ID: <expunged-mailbox@local.test>\r\n\r\n"
        val fixture = probeFixture(
            response = (
                successfulReadPrefix() +
                    "* SEARCH 7\r\n" +
                    "A004 OK Search completed\r\n" +
                    "* 1 EXPUNGE\r\n" +
                    "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${validLiteral.length}}\r\n" +
                    validLiteral +
                    ")\r\n" +
                    "A005 OK Fetch completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            secret = "expunged-mailbox-secret",
            requireMailboxRead = true,
        )

        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            fixture.probe.probe(TARGET, fixture.credential),
        )
        assertClosedAndWiped(fixture, "expunged-mailbox-secret")
    }

    @Test
    fun fullMailboxReadRejectsExistsDecreaseWithoutExpunge() {
        val validLiteral =
            "Message-ID: <decreased-exists@local.test>\r\n\r\n"
        val fixture = probeFixture(
            response = (
                successfulReadPrefixBeforeExamineState() +
                    "* 2 EXISTS\r\n" +
                    "A003 OK [READ-ONLY] Examine completed\r\n" +
                    "* SEARCH 7 9\r\n" +
                    "A004 OK Search completed\r\n" +
                    "* 1 EXISTS\r\n" +
                    "* 1 FETCH (UID 7 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${validLiteral.length}}\r\n" +
                    validLiteral +
                    ")\r\n" +
                    "A005 OK Fetch completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            secret = "decreased-exists-secret",
            requireMailboxRead = true,
        )

        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            fixture.probe.probe(TARGET, fixture.credential),
        )
        assertClosedAndWiped(fixture, "decreased-exists-secret")
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
    fun authenticateLoginClassifiesExactPermanentFailuresByKind() {
        listOf(
            "A001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n" to
                DovecotOperatorProbeResult.AuthenticationFailure,
            "A001 NO [AUTHORIZATIONFAILED] Authorization failed\r\n" to
                DovecotOperatorProbeResult.AuthorizationFailure,
            "A001 NO Authentication failed\r\n" to
                DovecotOperatorProbeResult.ProtocolFailure,
            "A001 NO [UNAVAILABLE] Authentication unavailable\r\n" to
                DovecotOperatorProbeResult.ProtocolFailure,
            "A001 NO [SERVERBUG] Authentication failed\r\n" to
                DovecotOperatorProbeResult.ProtocolFailure,
            "A001 BAD Invalid command\r\n" to
                DovecotOperatorProbeResult.ProtocolFailure,
        ).forEach { (completion, expected) ->
            val canary = "Canary-${completion.hashCode()}"
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
    fun typedResultsRemainProvisionalUntilFiniteCloseCompletes() {
        val cases = listOf(
            ProbeCloseCase(
                name = "success",
                response = successfulReadPrefixBeforeExamineState()
                    .toByteArray(StandardCharsets.US_ASCII),
                expected = DovecotOperatorProbeResult.Success,
            ),
            ProbeCloseCase(
                name = "authentication",
                response = (
                    "* OK ready\r\n" +
                        "+ VXNlcm5hbWU6\r\n" +
                        "+ UGFzc3dvcmQ6\r\n" +
                        "A001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n"
                    ).toByteArray(StandardCharsets.US_ASCII),
                expected = DovecotOperatorProbeResult.AuthenticationFailure,
            ),
            ProbeCloseCase(
                name = "authorization",
                response = (
                    "* OK ready\r\n" +
                        "+ VXNlcm5hbWU6\r\n" +
                        "+ UGFzc3dvcmQ6\r\n" +
                        "A001 NO [AUTHORIZATIONFAILED] Authorization failed\r\n"
                    ).toByteArray(StandardCharsets.US_ASCII),
                expected = DovecotOperatorProbeResult.AuthorizationFailure,
            ),
            ProbeCloseCase(
                name = "protocol",
                response = "* BAD invalid greeting\r\n"
                    .toByteArray(StandardCharsets.US_ASCII),
                expected = DovecotOperatorProbeResult.ProtocolFailure,
            ),
        )

        cases.forEach { case ->
            val closeStarted = CountDownLatch(1)
            val releaseClose = CountDownLatch(1)
            val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
            val transport = ScriptedCloseTransport(
                response = case.response,
                onClose = {
                    closeStarted.countDown()
                    releaseClose.await()
                },
            )
            val secretBytes =
                "provisional-${case.name}-secret"
                    .toByteArray(StandardCharsets.US_ASCII)
            val credential = DovecotOperatorCredential(
                DovecotOperatorId.A,
                DovecotOperatorSecret.takeOwnership(secretBytes),
            )
            val normalized = AtomicReference<DovecotOperatorProbeResult>()
            val probe = DovecotOperatorProbe(
                transportFactory = registeredFactory(transport),
                operationWorkers = workers,
                beforeResultNormalization = normalized::set,
            )
            val result = AtomicReference<DovecotOperatorProbeResult>()
            val failure = AtomicReference<Throwable>()
            val caller = Thread(
                {
                    try {
                        result.set(probe.probe(TARGET, credential))
                    } catch (caught: Throwable) {
                        failure.set(caught)
                    }
                },
                "test-provisional-${case.name}-probe",
            ).also {
                it.isDaemon = true
                it.start()
            }

            try {
                assertTrue(closeStarted.await(1, TimeUnit.SECONDS))
                caller.join(300)

                assertTrue(
                    caller.isAlive,
                    "${case.name} escaped before synchronous close",
                )
                assertNull(result.get())
                assertNull(normalized.get())
                assertEquals(
                    DovecotBoundedOperationSnapshot(
                        activeOperations = 1,
                        activeActors = 1,
                        peakActors = 1,
                    ),
                    workers.snapshot(),
                )
                assertEquals(0, transport.abortCalls.get())
                assertEquals(
                    listOf(DovecotBoundedActorRole.Io),
                    transport.closeRoles(),
                )
            } finally {
                releaseClose.countDown()
                caller.join(2_000)
            }

            assertFalse(caller.isAlive)
            assertNull(failure.get())
            assertEquals(case.expected, result.get())
            assertEquals(case.expected, normalized.get())
            assertEquals(1, transport.closeCalls.get())
            assertTrue(transport.closed)
            assertTrue(secretBytes.all { byte -> byte == 0.toByte() })
            assertProbeEventually {
                workers.snapshot() ==
                    DovecotBoundedOperationSnapshot(peakActors = 1)
            }
        }
    }

    @Test
    fun failedFiniteCloseReturnsTransportFailureAndRetainsCleanupOwnership() {
        val firstCloseAttempted = CountDownLatch(1)
        val cancellationStarted = CountDownLatch(2)
        val releaseCancellation = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = ScriptedCloseTransport(
            response = successfulReadPrefixBeforeExamineState()
                .toByteArray(StandardCharsets.US_ASCII),
            onAbort = {
                cancellationStarted.countDown()
                releaseCancellation.await()
            },
            onClose = { call ->
                if (call == 1) {
                    firstCloseAttempted.countDown()
                    throw IOException("injected finite close failure")
                }
                cancellationStarted.countDown()
                releaseCancellation.await()
            },
        )
        val secretBytes =
            "failed-finite-close-secret".toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(secretBytes),
        )
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val failure = AtomicReference<Throwable>()
        val caller = startProbeCaller(
            name = "test-failed-finite-close-probe",
            probe = DovecotOperatorProbe(
                transportFactory = registeredFactory(transport),
                operationWorkers = workers,
            ),
            credential = credential,
            result = result,
            failure = failure,
        )

        try {
            assertTrue(firstCloseAttempted.await(1, TimeUnit.SECONDS))
            assertTrue(cancellationStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)

            assertFalse(caller.isAlive)
            assertNull(failure.get())
            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                result.get(),
            )
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 2,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )
            assertNull(workers.tryAcquire(deadlineAfter()))
            assertTrue(secretBytes.all { byte -> byte == 0.toByte() })
        } finally {
            releaseCancellation.countDown()
            caller.join(2_000)
        }

        assertProbeEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 3)
        }
    }

    @Test
    fun finiteCloseDeadlineReturnsTransportFailureAndRetainsCleanupOwnership() {
        val normalCloseStarted = CountDownLatch(1)
        val cancellationStarted = CountDownLatch(2)
        val releaseCancellation = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = ScriptedCloseTransport(
            response = successfulReadPrefixBeforeExamineState()
                .toByteArray(StandardCharsets.US_ASCII),
            onAbort = {
                cancellationStarted.countDown()
                releaseCancellation.await()
            },
            onClose = { call ->
                if (call == 1) {
                    normalCloseStarted.countDown()
                } else {
                    cancellationStarted.countDown()
                }
                releaseCancellation.await()
            },
        )
        val secretBytes =
            "finite-close-deadline-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(secretBytes),
        )
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val failure = AtomicReference<Throwable>()
        val caller = startProbeCaller(
            name = "test-finite-close-deadline-probe",
            probe = DovecotOperatorProbe(
                transportFactory = registeredFactory(transport),
                clock = shortProbeDeadlineClock(),
                operationWorkers = workers,
            ),
            credential = credential,
            result = result,
            failure = failure,
        )

        try {
            assertTrue(normalCloseStarted.await(1, TimeUnit.SECONDS))
            assertTrue(cancellationStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)

            assertFalse(caller.isAlive)
            assertNull(failure.get())
            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                result.get(),
            )
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )
            assertNull(workers.tryAcquire(deadlineAfter()))
            assertTrue(secretBytes.all { byte -> byte == 0.toByte() })
        } finally {
            releaseCancellation.countDown()
            caller.join(2_000)
        }

        assertProbeEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 3)
        }
    }

    @Test
    fun callerInterruptedDuringFiniteCloseReturnsTransportFailureAndRetainsOwnership() {
        val normalCloseStarted = CountDownLatch(1)
        val cancellationStarted = CountDownLatch(2)
        val releaseCancellation = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val transport = ScriptedCloseTransport(
            response = successfulReadPrefixBeforeExamineState()
                .toByteArray(StandardCharsets.US_ASCII),
            onAbort = {
                cancellationStarted.countDown()
                releaseCancellation.await()
            },
            onClose = { call ->
                if (call == 1) {
                    normalCloseStarted.countDown()
                } else {
                    cancellationStarted.countDown()
                }
                releaseCancellation.await()
            },
        )
        val secretBytes =
            "interrupted-finite-close-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(secretBytes),
        )
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val failure = AtomicReference<Throwable>()
        val interruptRestored = AtomicBoolean()
        val caller = Thread(
            {
                try {
                    result.set(
                        DovecotOperatorProbe(
                            transportFactory = registeredFactory(transport),
                            operationWorkers = workers,
                        ).probe(TARGET, credential),
                    )
                    interruptRestored.set(
                        Thread.currentThread().isInterrupted,
                    )
                } catch (caught: Throwable) {
                    failure.set(caught)
                } finally {
                    Thread.interrupted()
                }
            },
            "test-interrupted-finite-close-probe",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(normalCloseStarted.await(1, TimeUnit.SECONDS))
            caller.interrupt()
            assertTrue(cancellationStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)

            assertFalse(caller.isAlive)
            assertNull(failure.get())
            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                result.get(),
            )
            assertTrue(interruptRestored.get())
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                workers.snapshot(),
            )
            assertNull(workers.tryAcquire(deadlineAfter()))
            assertTrue(secretBytes.all { byte -> byte == 0.toByte() })
        } finally {
            releaseCancellation.countDown()
            caller.join(2_000)
        }

        assertProbeEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 3)
        }
    }

    @Test
    fun allocatedCallbackFailureReturnsTransportFailureWithBothTargetsOwned() {
        val cancellationStarted = CountDownLatch(4)
        val releaseCancellation = CountDownLatch(1)
        val workers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val first = ScriptedCloseTransport(
            response = ByteArray(0),
            onAbort = {
                cancellationStarted.countDown()
                releaseCancellation.await()
            },
            onClose = {
                cancellationStarted.countDown()
                releaseCancellation.await()
            },
        )
        val second = ScriptedCloseTransport(
            response = ByteArray(0),
            onAbort = {
                cancellationStarted.countDown()
                releaseCancellation.await()
            },
            onClose = {
                cancellationStarted.countDown()
                releaseCancellation.await()
            },
        )
        val secretBytes =
            "allocated-callback-failure-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(secretBytes),
        )
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val failure = AtomicReference<Throwable>()
        val caller = startProbeCaller(
            name = "test-allocated-callback-failure-probe",
            probe = DovecotOperatorProbe(
                transportFactory = DovecotOperatorTransportFactory { register ->
                    register(first)
                    register(second)
                    error("a second allocation callback must be rejected")
                },
                operationWorkers = workers,
            ),
            credential = credential,
            result = result,
            failure = failure,
        )

        try {
            assertTrue(cancellationStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)

            assertFalse(caller.isAlive)
            assertNull(failure.get())
            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                result.get(),
            )
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 4,
                    peakActors = 5,
                ),
                workers.snapshot(),
            )
            assertNull(workers.tryAcquire(deadlineAfter()))
            assertTrue(secretBytes.all { byte -> byte == 0.toByte() })
        } finally {
            releaseCancellation.countDown()
            caller.join(2_000)
        }

        assertProbeEventually {
            workers.snapshot() ==
                DovecotBoundedOperationSnapshot(peakActors = 5)
        }
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
    fun dualBlockedCancellationCannotHoldProbeCallerPastItsAbsoluteDeadline() {
        val writeStarted = CountDownLatch(1)
        val abortStarted = CountDownLatch(1)
        val closeStarted = CountDownLatch(1)
        val releaseWrite = CountDownLatch(1)
        val releaseAbort = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val transport = TripleBlockingTransport(
            writeStarted = writeStarted,
            abortStarted = abortStarted,
            closeStarted = closeStarted,
            releaseWrite = releaseWrite,
            releaseAbort = releaseAbort,
            releaseClose = releaseClose,
        )
        val deadlineClock = shortProbeDeadlineClock()
        val operationWorkers = DovecotBoundedOperationWorkers(maxOperations = 1)
        val credentialBytes = "dual-blocked-probe-secret".toByteArray()
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(credentialBytes),
        )
        val probe = DovecotOperatorProbe(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            clock = deadlineClock,
            operationWorkers = operationWorkers,
        )
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val failure = AtomicReference<Throwable>()
        val caller = Thread(
            {
                try {
                    result.set(probe.probe(TARGET, credential))
                } catch (caught: Throwable) {
                    failure.set(caught)
                }
            },
            "test-dual-blocked-probe-caller",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(writeStarted.await(1, TimeUnit.SECONDS))
            assertTrue(abortStarted.await(1, TimeUnit.SECONDS))
            assertTrue(closeStarted.await(1, TimeUnit.SECONDS))
            caller.join(1_000)

            assertFalse(
                caller.isAlive,
                "write, abort, and close must not hold the probe caller",
            )
            assertEquals(null, failure.get())
            assertEquals(DovecotOperatorProbeResult.TransportFailure, result.get())
            assertTrue(credentialBytes.all { it == 0.toByte() })
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = 1,
                    activeActors = 3,
                    peakActors = 3,
                ),
                operationWorkers.snapshot(),
            )
        } finally {
            releaseWrite.countDown()
            releaseAbort.countDown()
            releaseClose.countDown()
            caller.join(2_000)
        }

        assertProbeEventually {
            operationWorkers.snapshot().let { snapshot ->
                snapshot.activeOperations == 0 &&
                    snapshot.abandonedOperations == 0 &&
                    snapshot.activeActors == 0
            }
        }
        assertTrue(transport.writeReferencesWereWiped())
    }

    @Test
    fun fourDualBlockedProbesFillCapacityBeforeAFifthTransportAllocation() {
        val operationCount = 4
        val callersReady = CountDownLatch(operationCount)
        val startCallers = CountDownLatch(1)
        val writeStarted = CountDownLatch(operationCount)
        val abortStarted = CountDownLatch(operationCount)
        val closeStarted = CountDownLatch(operationCount)
        val releaseWrite = CountDownLatch(1)
        val releaseAbort = CountDownLatch(1)
        val releaseClose = CountDownLatch(1)
        val blockingPhase = AtomicBoolean(true)
        val allocations = AtomicInteger()
        val transports = mutableListOf<TripleBlockingTransport>()
        val recoveryTransport = AtomicReference<RecordingTransport>()
        val transportFactory = DovecotOperatorTransportFactory { register ->
            allocations.incrementAndGet()
            if (blockingPhase.get()) {
                TripleBlockingTransport(
                    writeStarted = writeStarted,
                    abortStarted = abortStarted,
                    closeStarted = closeStarted,
                    releaseWrite = releaseWrite,
                    releaseAbort = releaseAbort,
                    releaseClose = releaseClose,
                ).also { transport ->
                    synchronized(transports) {
                        transports += transport
                    }
                    register(transport)
                }
            } else {
                RecordingTransport(
                    ByteArrayInputStream(successfulReadPrefix().toByteArray()),
                ).also { transport ->
                    recoveryTransport.set(transport)
                    register(transport)
                }
            }
        }
        val operationWorkers =
            DovecotBoundedOperationWorkers(maxOperations = operationCount)
        val deadlineClock = shortProbeDeadlineClock()
        val probe = DovecotOperatorProbe(
            transportFactory = transportFactory,
            clock = deadlineClock,
            operationWorkers = operationWorkers,
        )
        val credentialBytes = List(operationCount) { index ->
            "capacity-probe-secret-$index".toByteArray()
        }
        val results = List(operationCount) {
            AtomicReference<DovecotOperatorProbeResult>()
        }
        val failures = List(operationCount) { AtomicReference<Throwable>() }
        val callers = List(operationCount) { index ->
            val credential = DovecotOperatorCredential(
                DovecotOperatorId.A,
                DovecotOperatorSecret.takeOwnership(credentialBytes[index]),
            )
            Thread(
                {
                    callersReady.countDown()
                    startCallers.await()
                    try {
                        results[index].set(probe.probe(TARGET, credential))
                    } catch (caught: Throwable) {
                        failures[index].set(caught)
                    }
                },
                "test-capacity-probe-caller-$index",
            ).also {
                it.isDaemon = true
                it.start()
            }
        }

        try {
            assertTrue(callersReady.await(1, TimeUnit.SECONDS))
            startCallers.countDown()
            assertTrue(writeStarted.await(2, TimeUnit.SECONDS))
            assertTrue(abortStarted.await(2, TimeUnit.SECONDS))
            assertTrue(closeStarted.await(2, TimeUnit.SECONDS))
            callers.forEach { caller -> caller.join(1_000) }

            assertTrue(callers.none(Thread::isAlive))
            assertTrue(failures.all { failure -> failure.get() == null })
            assertTrue(
                results.all { result ->
                    result.get() == DovecotOperatorProbeResult.TransportFailure
                },
            )
            assertTrue(
                credentialBytes.all { bytes ->
                    bytes.all { it == 0.toByte() }
                },
            )
            assertEquals(
                DovecotBoundedOperationSnapshot(
                    abandonedOperations = operationCount,
                    activeActors = operationCount * 3,
                    peakActors = operationCount * 3,
                ),
                operationWorkers.snapshot(),
            )

            val fifthCredentialBytes = "rejected-capacity-secret".toByteArray()
            val fifthCredential = DovecotOperatorCredential(
                DovecotOperatorId.A,
                DovecotOperatorSecret.takeOwnership(fifthCredentialBytes),
            )
            val allocationsBeforeFifth = allocations.get()
            val actorsBeforeFifth = operationWorkers.snapshot().activeActors

            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                probe.probe(TARGET, fifthCredential),
            )
            assertEquals(allocationsBeforeFifth, allocations.get())
            assertEquals(
                actorsBeforeFifth,
                operationWorkers.snapshot().activeActors,
            )
            assertTrue(fifthCredentialBytes.all { it == 0.toByte() })
        } finally {
            startCallers.countDown()
            releaseWrite.countDown()
            releaseAbort.countDown()
            releaseClose.countDown()
            callers.forEach { caller -> caller.join(2_000) }
        }

        assertProbeEventually {
            operationWorkers.snapshot().let { snapshot ->
                snapshot.activeOperations == 0 &&
                    snapshot.abandonedOperations == 0 &&
                    snapshot.activeActors == 0
            }
        }
        val blockingTransports = synchronized(transports) {
            transports.toList()
        }
        assertEquals(operationCount, blockingTransports.size)
        assertTrue(
            blockingTransports.all(
                TripleBlockingTransport::writeReferencesWereWiped,
            ),
        )

        blockingPhase.set(false)
        val recoveryCredentialBytes = "capacity-recovery-secret".toByteArray()
        val recoveryCredential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(recoveryCredentialBytes),
        )
        val recoveryProbe = DovecotOperatorProbe(
            transportFactory = transportFactory,
            operationWorkers = operationWorkers,
        )

        assertEquals(
            DovecotOperatorProbeResult.Success,
            recoveryProbe.probe(TARGET, recoveryCredential),
        )
        assertTrue(recoveryCredentialBytes.all { it == 0.toByte() })
        assertTrue(recoveryTransport.get().closed)
        assertProbeEventually {
            operationWorkers.snapshot().let { snapshot ->
                snapshot.activeOperations == 0 &&
                    snapshot.abandonedOperations == 0 &&
                    snapshot.activeActors == 0
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
    fun blockedAbortCannotPreventIndependentCloseAndProbeCompletion() {
        val writeStarted = CountDownLatch(1)
        val abortStarted = CountDownLatch(1)
        val releaseWrite = CountDownLatch(1)
        val releaseAbort = CountDownLatch(1)
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
                    writeStarted.countDown()
                    releaseWrite.await()
                    throw IOException("closed")
                }
            }

            override fun abort() {
                abortStarted.countDown()
                releaseAbort.await()
            }

            override fun close() {
                closed = true
                releaseWrite.countDown()
            }
        }
        val credentialBytes = "blocking-abort-secret".toByteArray()
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
                    "test-blocking-abort-watchdog",
                ).also {
                    it.isDaemon = true
                    it.start()
                }
                AutoCloseable {}
            },
        )
        val result = AtomicReference<DovecotOperatorProbeResult>()
        val caller = Thread(
            {
                result.set(probe.probe(TARGET, credential))
            },
            "test-blocking-abort-probe",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            assertTrue(abortStarted.await(2, TimeUnit.SECONDS))
            caller.join(1_000)

            assertFalse(caller.isAlive)
            assertTrue(transport.closed)
            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                result.get(),
            )
            assertTrue(credentialBytes.all { it == 0.toByte() })
        } finally {
            releaseAbort.countDown()
            releaseWrite.countDown()
            caller.join(2_000)
        }
    }

    @Test
    fun watchdogCancelsBlockedOpenAndLateTransportSelfAborts() {
        val openStarted = CountDownLatch(1)
        val releaseOpen = CountDownLatch(1)
        val operationWorkers =
            DovecotBoundedOperationWorkers(maxOperations = 1)
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
                releaseOpen.await()
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
            operationWorkers = operationWorkers,
        )

        try {
            assertEquals(
                DovecotOperatorProbeResult.TransportFailure,
                probe.probe(TARGET, credential),
            )
            val abortDeadline =
                System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (!transport.closed && System.nanoTime() < abortDeadline) {
                Thread.sleep(10)
            }
            assertTrue(transport.closed)
            assertTrue(credentialBytes.all { it == 0.toByte() })
            assertTrue(transport.output.snapshots.isEmpty())
        } finally {
            releaseOpen.countDown()
        }
        assertProbeEventually {
            operationWorkers.snapshot().let { snapshot ->
                snapshot.activeOperations == 0 &&
                    snapshot.abandonedOperations == 0 &&
                    snapshot.activeActors == 0
            }
        }
    }

    @Test
    fun callerInterruptionCancelsBlockedOpenAndRestoresInterruptStatus() {
        val openStarted = CountDownLatch(1)
        val releaseOpen = CountDownLatch(1)
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
                releaseOpen.await()
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
        releaseOpen.countDown()

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

    @Test
    fun callerInterruptedAfterSuccessSelectionReturnsTransportFailure() {
        val selected = AtomicReference<DovecotOperatorProbeResult>()
        val fixture = probeFixture(
            response = successfulReadPrefixBeforeExamineState()
                .toByteArray(StandardCharsets.US_ASCII),
            secret = "interrupted-success-selection-secret",
            beforeResultNormalization = { result ->
                selected.set(result)
                Thread.currentThread().interrupt()
            },
        )

        val result = probeWithCapturedInterrupt(fixture)

        assertEquals(DovecotOperatorProbeResult.Success, selected.get())
        assertEquals(DovecotOperatorProbeResult.TransportFailure, result)
        assertClosedAndWiped(
            fixture,
            "interrupted-success-selection-secret",
        )
        assertProbeReleased(fixture)
    }

    @Test
    fun callerInterruptedAfterEarlyAuthenticationSelectionReturnsTransportFailure() {
        val selected = AtomicReference<DovecotOperatorProbeResult>()
        val fixture = probeFixture(
            response = (
                "* OK ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 NO [AUTHENTICATIONFAILED] Authentication failed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
            secret = "interrupted-auth-selection-secret",
            beforeResultNormalization = { result ->
                selected.set(result)
                Thread.currentThread().interrupt()
            },
        )

        val result = probeWithCapturedInterrupt(fixture)

        assertEquals(
            DovecotOperatorProbeResult.AuthenticationFailure,
            selected.get(),
        )
        assertEquals(DovecotOperatorProbeResult.TransportFailure, result)
        assertClosedAndWiped(fixture, "interrupted-auth-selection-secret")
        assertProbeReleased(fixture)
    }

    @Test
    fun callerInterruptedAfterProtocolCatchReturnsTransportFailure() {
        val selected = AtomicReference<DovecotOperatorProbeResult>()
        val fixture = probeFixture(
            response = "* BAD invalid greeting\r\n"
                .toByteArray(StandardCharsets.US_ASCII),
            secret = "interrupted-protocol-selection-secret",
            beforeResultNormalization = { result ->
                selected.set(result)
                Thread.currentThread().interrupt()
            },
        )

        val result = probeWithCapturedInterrupt(fixture)

        assertEquals(
            DovecotOperatorProbeResult.ProtocolFailure,
            selected.get(),
        )
        assertEquals(DovecotOperatorProbeResult.TransportFailure, result)
        assertClosedAndWiped(
            fixture,
            "interrupted-protocol-selection-secret",
        )
        assertProbeReleased(fixture)
    }

    private fun probeWithCapturedInterrupt(
        fixture: ProbeFixture,
    ): DovecotOperatorProbeResult {
        try {
            val result = fixture.probe.probe(TARGET, fixture.credential)
            assertTrue(Thread.currentThread().isInterrupted)
            return result
        } finally {
            Thread.interrupted()
        }
    }

    private fun probeFixture(
        response: ByteArray,
        secret: String,
        inputFactory: (ByteArray) -> InputStream = ::ByteArrayInputStream,
        clock: DovecotOperatorProbeClock = DovecotOperatorProbeClock(System::nanoTime),
        requireMailboxRead: Boolean = false,
        beforeResultNormalization: (DovecotOperatorProbeResult) -> Unit = {},
    ): ProbeFixture {
        val transport = RecordingTransport(inputFactory(response))
        val secretBytes = secret.toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            DovecotOperatorId.A,
            DovecotOperatorSecret.takeOwnership(secretBytes),
        )
        val workers = DovecotBoundedOperationWorkers(
            nanoTime = clock::nanoTime,
        )
        return ProbeFixture(
            probe = DovecotOperatorProbe(
                transportFactory = DovecotOperatorTransportFactory { register ->
                    register(transport)
                    transport
                },
                clock = clock,
                requireMailboxRead = requireMailboxRead,
                operationWorkers = workers,
                beforeResultNormalization = beforeResultNormalization,
            ),
            transport = transport,
            credential = credential,
            secretBytes = secretBytes,
            workers = workers,
        )
    }

    private fun assertClosedAndWiped(
        fixture: ProbeFixture,
        canary: String,
    ) {
        assertProbeReleased(fixture)
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

    private fun assertProbeReleased(fixture: ProbeFixture) {
        assertProbeEventually {
            fixture.workers.snapshot().let { snapshot ->
                snapshot.activeOperations == 0 &&
                    snapshot.abandonedOperations == 0 &&
                    snapshot.activeActors == 0
            }
        }
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

    private class ScriptedCloseTransport(
        response: ByteArray,
        private val onAbort: () -> Unit = {},
        private val onClose: (Int) -> Unit = {},
    ) : DovecotOperatorTransport {
        override val input: InputStream = ByteArrayInputStream(response)
        override val outputStream: OutputStream = RecordingOutputStream()
        val abortCalls = AtomicInteger()
        val closeCalls = AtomicInteger()
        private val closeThreadNames = mutableListOf<String>()

        @Volatile
        var closed = false
            private set

        override fun abort() {
            abortCalls.incrementAndGet()
            onAbort()
        }

        override fun close() {
            val call = closeCalls.incrementAndGet()
            synchronized(closeThreadNames) {
                closeThreadNames += Thread.currentThread().name
            }
            onClose(call)
            closed = true
        }

        fun closeRoles(): List<DovecotBoundedActorRole> =
            synchronized(closeThreadNames) {
                closeThreadNames.map { name ->
                    when {
                        name.startsWith("dovecot-bounded-operation-io-") ->
                            DovecotBoundedActorRole.Io
                        name.startsWith("dovecot-bounded-operation-close-") ->
                            DovecotBoundedActorRole.Close
                        else -> error("Unexpected close thread: $name")
                    }
                }
            }
    }

    private class TripleBlockingTransport(
        private val writeStarted: CountDownLatch,
        private val abortStarted: CountDownLatch,
        private val closeStarted: CountDownLatch,
        private val releaseWrite: CountDownLatch,
        private val releaseAbort: CountDownLatch,
        private val releaseClose: CountDownLatch,
    ) : DovecotOperatorTransport {
        private val writeReferences = mutableListOf<ByteArray>()

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
                assertEquals(0, offset)
                assertEquals(bytes.size, length)
                synchronized(writeReferences) {
                    writeReferences += bytes
                }
                writeStarted.countDown()
                releaseWrite.await()
                throw IOException("released blocked probe write")
            }
        }

        override fun abort() {
            abortStarted.countDown()
            releaseAbort.await()
        }

        override fun close() {
            closeStarted.countDown()
            releaseClose.await()
        }

        fun writeReferencesWereWiped(): Boolean =
            synchronized(writeReferences) {
                writeReferences.isNotEmpty() &&
                    writeReferences.all { bytes ->
                        bytes.all { it == 0.toByte() }
                    }
            }

        override fun toString(): String = "TripleBlockingTransport(redacted)"
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
        val workers: DovecotBoundedOperationWorkers,
    )

    private data class ProbeCloseCase(
        val name: String,
        val response: ByteArray,
        val expected: DovecotOperatorProbeResult,
    )

    private fun registeredFactory(
        transport: DovecotOperatorTransport,
    ): DovecotOperatorTransportFactory =
        DovecotOperatorTransportFactory { register ->
            register(transport)
            transport
        }

    private fun startProbeCaller(
        name: String,
        probe: DovecotOperatorProbe,
        credential: DovecotOperatorCredential,
        result: AtomicReference<DovecotOperatorProbeResult>,
        failure: AtomicReference<Throwable>,
    ): Thread =
        Thread(
            {
                try {
                    result.set(probe.probe(TARGET, credential))
                } catch (caught: Throwable) {
                    failure.set(caught)
                }
            },
            name,
        ).also {
            it.isDaemon = true
            it.start()
        }

    private fun deadlineAfter(): Long =
        System.nanoTime() + TimeUnit.SECONDS.toNanos(2)

    private fun shortProbeDeadlineClock(): DovecotOperatorProbeClock {
        val productionDeadlineNanos = TimeUnit.SECONDS.toNanos(5)
        val testDeadlineNanos = TimeUnit.MILLISECONDS.toNanos(200)
        return DovecotOperatorProbeClock {
            System.nanoTime() - productionDeadlineNanos + testDeadlineNanos
        }
    }

    private fun assertProbeEventually(assertion: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
        while (!assertion() && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertTrue(assertion())
    }

    private fun assertSearchAllUidCountMatchesExists(
        response: ByteArray,
    ) {
        val transcript = response.toString(StandardCharsets.US_ASCII)
        val existsMatches = Regex(
            """\* ([1-9][0-9]*) EXISTS\r\n""",
        ).findAll(transcript).toList()
        val searchMatches = Regex(
            """\* SEARCH ([1-9][0-9]*(?: [1-9][0-9]*)*)\r\n""",
        ).findAll(transcript).toList()
        assertEquals(
            1,
            existsMatches.size,
            "A successful full-read transcript must declare one EXISTS count",
        )
        assertEquals(
            1,
            searchMatches.size,
            "A successful full-read transcript must return one SEARCH result",
        )
        val existsCount = existsMatches.single().groupValues[1].toInt()
        val searchedUidCount =
            searchMatches.single().groupValues[1].split(' ').size
        assertEquals(
            existsCount,
            searchedUidCount,
            "UID SEARCH ALL must return one UID per declared message",
        )
    }

    companion object {
        private val TARGET = DovecotOperatorTarget.create("probe-target@local.test")
        private val DEADLINE_CLOCK = AtomicLong()

        private fun successfulReadPrefix(): String =
            successfulReadPrefixBeforeExamineState() +
                "* 1 EXISTS\r\n" +
                "A003 OK [READ-ONLY] Examine completed\r\n"

        private fun successfulReadPrefixBeforeExamineState(): String =
            "* OK Dovecot ready\r\n" +
                "+ VXNlcm5hbWU6\r\n" +
                "+ UGFzc3dvcmQ6\r\n" +
                "A001 OK Logged in\r\n" +
                "* LIST (\\HasNoChildren) \".\" INBOX\r\n" +
                "A002 OK List completed\r\n"
    }
}
