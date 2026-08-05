package mail.sandbox.dashboard.server.gate.stalwart

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.ArrayDeque
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

class StalwartGateLiveContractSupportTest {
    @Test
    fun strictMethodPayloadRequiresOneMatchingTuple() {
        val payload = buildJsonObject { put("accountId", "account-1") }

        assertEquals(
            payload,
            requireSingleJmapMethodPayload(
                response = methodResponse("Email/get", payload),
                expectedMethod = "Email/get",
            ),
        )

        val failure = assertFailsWith<GateJmapException> {
            requireSingleJmapMethodPayload(
                response = buildJsonObject {
                    put(
                        "methodResponses",
                        buildJsonArray {
                            add(methodTuple("Email/get", payload, "call-1"))
                            add(methodTuple("Email/get", payload, "call-2"))
                        },
                    )
                },
                expectedMethod = "Email/get",
            )
        }
        assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
        assertFailsWith<GateJmapException> {
            requireSingleJmapMethodPayload(
                response = methodResponse("Mailbox/get", payload),
                expectedMethod = "Email/get",
            )
        }
    }

    @Test
    fun emailSetBuilderIncludesStateAndPreservesExplicitPatchPaths() {
        val arguments = buildEmailSetUpdateArguments(
            accountId = "account-1",
            ifInState = "state-before",
            updates = linkedMapOf(
                "email-real" to buildJsonObject {
                    put("mailboxIds/target", true)
                    put("mailboxIds/source", JsonNull)
                    put("keywords/\$seen", true)
                    put("keywords/\$flagged", false)
                },
                "email-missing" to buildJsonObject {
                    put("keywords/\$seen", true)
                },
            ),
        )

        assertEquals("account-1", arguments["accountId"]?.let(::requiredTestString))
        assertEquals("state-before", arguments["ifInState"]?.let(::requiredTestString))
        assertEquals(
            linkedSetOf("email-real", "email-missing"),
            arguments["update"]?.jsonObject?.keys,
        )
        assertEquals(
            JsonNull,
            arguments["update"]
                ?.jsonObject
                ?.get("email-real")
                ?.jsonObject
                ?.get("mailboxIds/source"),
        )
    }

    @Test
    fun emailSetParserAccountsForMixedUpdatedAndNotUpdatedIds() {
        val response = methodResponse(
            method = "Email/set",
            payload = buildJsonObject {
                put("accountId", "account-1")
                put("oldState", "state-before")
                put("newState", "state-after")
                put(
                    "updated",
                    buildJsonObject {
                        put("email-real", JsonNull)
                    },
                )
                put(
                    "notUpdated",
                    buildJsonObject {
                        put(
                            "email-missing",
                            buildJsonObject {
                                put("type", "notFound")
                                put("description", "diagnostic text is not retained")
                            },
                        )
                    },
                )
            },
        )

        val parsed = assertIs<GateEmailSetResponse.Applied>(
            parseGateEmailSetResponse(
                response = response,
                expectedAccountId = "account-1",
                requestedIds = linkedSetOf("email-real", "email-missing"),
            ),
        )

        assertEquals("state-before", parsed.oldState)
        assertEquals("state-after", parsed.newState)
        assertEquals(
            linkedMapOf(
                "email-real" to GateEmailSetObjectOutcome.Updated,
                "email-missing" to GateEmailSetObjectOutcome.NotUpdated("notFound"),
            ),
            parsed.outcomes,
        )
        assertEquals(
            "GateEmailSetResponse.Applied(oldState=redacted, newState=redacted, outcomes={email-real=Updated, email-missing=NotUpdated(type=notFound)})",
            parsed.toString(),
        )
    }

    @Test
    fun emailSetParserRejectsContradictoryOrMissingOutcomes() {
        val contradictory = methodResponse(
            method = "Email/set",
            payload = buildJsonObject {
                put("accountId", "account-1")
                put("oldState", "before")
                put("newState", "after")
                put("updated", buildJsonObject { put("email-1", JsonNull) })
                put(
                    "notUpdated",
                    buildJsonObject {
                        put(
                            "email-1",
                            buildJsonObject { put("type", "notFound") },
                        )
                    },
                )
            },
        )
        val missing = methodResponse(
            method = "Email/set",
            payload = buildJsonObject {
                put("accountId", "account-1")
                put("oldState", "before")
                put("newState", "after")
                put("updated", buildJsonObject {})
                put("notUpdated", buildJsonObject {})
            },
        )

        listOf(contradictory, missing).forEach { response ->
            val failure = assertFailsWith<GateJmapException> {
                parseGateEmailSetResponse(
                    response = response,
                    expectedAccountId = "account-1",
                    requestedIds = setOf("email-1"),
                )
            }
            assertEquals(GateJmapFailure.InvalidResponse, failure.kind)
        }
    }

    @Test
    fun emailSetStateMismatchIsTheOnlyTypedConflict() {
        val conflict = requireGateEmailSetConflict(
            GateJmapException(
                kind = GateJmapFailure.MethodError("stateMismatch"),
                message = "JMAP method returned a typed error",
            ),
        )

        assertEquals(GateEmailSetResponse.Conflict("stateMismatch"), conflict)
        assertFailsWith<GateJmapException> {
            requireGateEmailSetConflict(
                GateJmapException(
                    kind = GateJmapFailure.MethodError("forbidden"),
                    message = "JMAP method returned a typed error",
                ),
            )
        }
    }

    @Test
    fun accountLedgerSetsIntentBeforeDispatchAndAdoptsOnlyExactOwnedProjection() {
        runBlocking {
            val ledger = GateOwnedAccountLedger(
                localPart = "gate-task7-0123456789abcdef",
                domainId = "domain-1",
                baselineAccountIds = setOf("baseline-account"),
            )
            assertFalse(ledger.createAttempted)

            assertFailsWith<LostResponse> {
                ledger.dispatchCreate {
                    assertTrue(ledger.createAttempted)
                    throw LostResponse()
                }
            }

            assertTrue(
                ledger.reconcileCandidate(
                    accountProjection(
                        id = "created-account",
                        name = "gate-task7-0123456789abcdef",
                        domainId = "domain-1",
                    ),
                ),
            )
            assertFalse(
                ledger.reconcileCandidate(
                    accountProjection(
                        id = "unrelated-account",
                        name = "gate-task7-another",
                        domainId = "domain-1",
                    ),
                ),
            )
            assertEquals(setOf("created-account"), ledger.cleanupIds)
            ledger.requireSafeToDestroy(
                id = "created-account",
                projection = accountProjection(
                    id = "created-account",
                    name = "gate-task7-0123456789abcdef",
                    domainId = "domain-1",
                ),
            )

            assertFailsWith<IllegalStateException> {
                ledger.reconcileCandidate(
                    accountProjection(
                        id = "collision-account",
                        name = "gate-task7-0123456789abcdef",
                        domainId = "other-domain",
                    ),
                )
            }
            assertFailsWith<IllegalStateException> {
                ledger.recordCreatedId("baseline-account")
            }
        }
    }

    @Test
    fun mailLedgerSetsIntentBeforeDispatchAndReconcilesExactMarkers() = runBlocking {
        val ledger = GateMailArtifactLedger(
            exactSubject = "Gate Task 7 marker 0123456789abcdef",
            exactMessageId = "<gate-task7-0123456789abcdef@local.test>",
            exactMailboxNames = setOf(
                "Gate Task 7 source 0123456789abcdef",
                "Gate Task 7 target 0123456789abcdef",
            ),
        )

        assertFailsWith<LostResponse> {
            ledger.dispatchMailboxCreate {
                assertTrue(ledger.mailboxCreateAttempted)
                throw LostResponse()
            }
        }
        assertFailsWith<LostResponse> {
            ledger.dispatchEmailImport {
                assertTrue(ledger.emailImportAttempted)
                throw LostResponse()
            }
        }

        assertTrue(
            ledger.reconcileMailboxCandidate(
                id = "mailbox-1",
                name = "Gate Task 7 source 0123456789abcdef",
            ),
        )
        assertFalse(
            ledger.reconcileMailboxCandidate(
                id = "mailbox-other",
                name = "Gate Task 7 source similar",
            ),
        )
        assertTrue(
            ledger.reconcileEmailCandidate(
                id = "email-1",
                subject = "Gate Task 7 marker 0123456789abcdef",
                messageIds = listOf("gate-task7-0123456789abcdef@local.test"),
            ),
        )
        assertFalse(
            ledger.reconcileEmailCandidate(
                id = "email-other",
                subject = "Gate Task 7 marker 0123456789abcdef",
                messageIds = listOf("another@local.test"),
            ),
        )
        assertEquals(setOf("mailbox-1"), ledger.mailboxCleanupIds)
        assertEquals(setOf("email-1"), ledger.emailCleanupIds)
    }

    @Test
    fun boundedSmtpReplyParsesMultilineAndClassifiesRejectionsWithoutText() {
        val lines = ArrayDeque(
            listOf(
                "550-mailbox unavailable",
                "550 5.1.2 recipient does not exist",
            ),
        )

        val reply = readBoundedGateSmtpReply { lines.pollFirst() }
        val outcome = reply.toRecipientOutcome()

        assertEquals(550, reply.code)
        assertEquals("5.1.2", reply.enhancedStatus)
        assertEquals(
            GateSmtpRecipientOutcome.PermanentRejected(
                code = 550,
                enhancedStatus = "5.1.2",
            ),
            outcome,
        )
        assertEquals(
            "GateSmtpReply(code=550, enhancedStatus=5.1.2, lineCount=2, text=redacted)",
            reply.toString(),
        )
        assertFalse(reply.toString().contains("recipient does not exist"))
    }

    @Test
    fun boundedSmtpReplyRejectsChangedCodesAndUnterminatedResponses() {
        val changedCodes = ArrayDeque(listOf("250-first", "550 final"))
        assertFailsWith<IllegalStateException> {
            readBoundedGateSmtpReply { changedCodes.pollFirst() }
        }

        var lineCount = 0
        assertFailsWith<IllegalStateException> {
            readBoundedGateSmtpReply {
                lineCount += 1
                "250-more"
            }
        }
        assertEquals(64, lineCount)
    }

    @Test
    fun smtpClientAuthenticatesAndFramesACompleteAcceptedDelivery() {
        val wire = ScriptedSmtpWire(
            "220 gate ready",
            "250-gate.local.test",
            "250 AUTH PLAIN",
            "235 2.7.0 authenticated",
            "250 2.1.0 sender accepted",
            "250 2.1.5 recipient accepted",
            "354 send message",
            "250 2.0.0 queued",
            "221 2.0.0 goodbye",
        )
        val secret = "smtp-test-secret".toCharArray()
        val result = GateSmtpClient(GateSmtpConnector { wire }).use { client ->
            client.send(
                username = "sender@local.test",
                secret = secret,
                envelopeFrom = "sender@local.test",
                envelopeRecipient = "recipient@local.test",
                rawMessage = completeMessage(
                    body = "first line\r\n.dot-prefixed line\r\n",
                ),
            )
        }

        val accepted = assertIs<GateSmtpDeliveryOutcome.Accepted>(result)
        assertEquals(250, accepted.recipient.code)
        assertEquals(250, accepted.queuedCode)
        assertEquals("2.0.0", accepted.queuedEnhancedStatus)
        assertTrue(wire.closed)
        val transcript = wire.written.toString(StandardCharsets.US_ASCII)
        assertTrue(transcript.startsWith("EHLO gate0b.local.test\r\nAUTH PLAIN "))
        assertTrue(transcript.contains("\r\nMAIL FROM:<sender@local.test>\r\n"))
        assertTrue(transcript.contains("RCPT TO:<recipient@local.test>\r\nDATA\r\n"))
        assertTrue(transcript.contains("\r\n..dot-prefixed line\r\n.\r\nQUIT\r\n"))
        val authLine = transcript.lineSequence()
            .firstOrNull { it.startsWith("AUTH PLAIN ") }
        assertNotNull(authLine)
        val challenge = Base64.getDecoder().decode(authLine.removePrefix("AUTH PLAIN "))
        try {
            assertEquals(
                "\u0000sender@local.test\u0000smtp-test-secret",
                challenge.toString(StandardCharsets.US_ASCII),
            )
        } finally {
            challenge.fill(0)
            secret.fill('\u0000')
        }
        assertFalse(result.toString().contains("smtp-test-secret"))
    }

    @Test
    fun smtpRecipientProbeReturnsAStablePermanentRejection() {
        val wire = ScriptedSmtpWire(
            "220 gate ready",
            "250-gate.local.test",
            "250 AUTH PLAIN",
            "235 2.7.0 authenticated",
            "250 2.1.0 sender accepted",
            "550 5.1.2 recipient does not exist",
            "250 2.0.0 reset",
            "221 2.0.0 goodbye",
        )
        val secret = "smtp-test-secret".toCharArray()
        val result = try {
            GateSmtpClient(GateSmtpConnector { wire }).use { client ->
                client.probeRecipient(
                    username = "sender@local.test",
                    secret = secret,
                    envelopeFrom = "sender@local.test",
                    envelopeRecipient = "deleted@local.test",
                )
            }
        } finally {
            secret.fill('\u0000')
        }

        assertEquals(
            GateSmtpRecipientOutcome.PermanentRejected(
                code = 550,
                enhancedStatus = "5.1.2",
            ),
            result,
        )
        val transcript = wire.written.toString(StandardCharsets.US_ASCII)
        assertTrue(transcript.endsWith("RCPT TO:<deleted@local.test>\r\n"))
        assertFalse(transcript.contains("RSET\r\n"))
        assertFalse(transcript.contains("QUIT\r\n"))
    }

    private fun methodResponse(method: String, payload: JsonObject): JsonObject =
        buildJsonObject {
            put(
                "methodResponses",
                JsonArray(listOf(methodTuple(method, payload, "call-1"))),
            )
        }

    private fun methodTuple(
        method: String,
        payload: JsonObject,
        callId: String,
    ): JsonArray =
        JsonArray(
            listOf(
                JsonPrimitive(method),
                payload,
                JsonPrimitive(callId),
            ),
        )

    private fun accountProjection(
        id: String,
        name: String,
        domainId: String,
    ): JsonObject = buildJsonObject {
        put("id", id)
        put("@type", "User")
        put("name", name)
        put("domainId", domainId)
    }

    private fun completeMessage(body: String): String = buildString {
        append("From: sender@local.test\r\n")
        append("To: recipient@local.test\r\n")
        append("Date: Wed, 5 Aug 2026 12:00:00 -0300\r\n")
        append("Subject: Gate support test\r\n")
        append("Message-ID: <gate-support-test@local.test>\r\n")
        append("MIME-Version: 1.0\r\n")
        append("Content-Type: text/plain; charset=UTF-8\r\n")
        append("\r\n")
        append(body)
    }

    private fun requiredTestString(value: kotlinx.serialization.json.JsonElement): String =
        (value as JsonPrimitive).content

    private class LostResponse : RuntimeException()

    private class ScriptedSmtpWire(
        vararg responseLines: String,
    ) : GateSmtpWire {
        private val responses = ArrayDeque(responseLines.toList())
        val written = ByteArrayOutputStream()
        var closed = false
            private set

        override fun readLine(): String? = responses.pollFirst()

        override fun write(bytes: ByteArray) {
            check(!closed)
            written.write(bytes)
        }

        override fun close() {
            closed = true
        }
    }
}
