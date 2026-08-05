package mail.sandbox.dashboard.server.gate.stalwart

import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

class StalwartMailMutationLiveTest {
    @Test
    fun provesStateSafeSameAccountMailboxAndKeywordMutations() = runBlocking {
        val environment = System.getenv()
        val projectRoot = dashboardProjectRoot()
        val live = StalwartLiveTestEnvironment.load(
            environment = environment,
            projectRoot = projectRoot,
        )
        live.awaitReady()
        StalwartDockerMountAudit.assertReviewedLiveMounts(projectRoot)

        StalwartGateSecretFiles.readFixtureSecrets(
            projectRoot = projectRoot,
            environment = environment,
        ).use { fixture ->
            KtorGateHttpTransport().use { transport ->
                GateJmapClient(
                    baseUrl = live.baseUrl,
                    credential = GateCredential.basic(
                        username = GateBootstrap.FIRST_USER_ADDRESS,
                        secret = fixture.firstUserPassword,
                    ),
                    transport = transport,
                ).use { owner ->
                    val session = owner.discoverSession()
                    val accountId = requirePrimaryAccount(session)
                    assertFalse(
                        accountId == fixture.managementAccountId,
                        "Ordinary mail mutation credential resolved to management",
                    )

                    val artifacts = MutationArtifacts(UUID.randomUUID().toString())
                    var primaryFailure: Throwable? = null
                    try {
                        exerciseMutations(
                            owner = owner,
                            accountId = accountId,
                            artifacts = artifacts,
                        )
                    } catch (failure: Throwable) {
                        primaryFailure = failure
                        throw failure
                    } finally {
                        withContext(NonCancellable) {
                            val cleanupFailure = runCatching {
                                cleanupExactArtifacts(
                                    owner = owner,
                                    accountId = accountId,
                                    artifacts = artifacts,
                                )
                            }.exceptionOrNull()
                            cleanupFailure?.let { failure ->
                                primaryFailure?.addSuppressed(failure)
                                    ?: throw failure
                            }
                        }
                    }
                }
            }
        }
    }

    private suspend fun exerciseMutations(
        owner: GateJmapClient,
        accountId: String,
        artifacts: MutationArtifacts,
    ) {
        val inboxId = requireInboxId(owner, accountId)
        val targetMailboxId = createTargetMailbox(
            owner = owner,
            accountId = accountId,
            artifacts = artifacts,
        )
        val blobId = uploadMarkedMessage(
            owner = owner,
            accountId = accountId,
            artifacts = artifacts,
        )
        val imported = importMarkedEmail(
            owner = owner,
            accountId = accountId,
            inboxId = inboxId,
            blobId = blobId,
            artifacts = artifacts,
        )
        val emailId = imported.emailId
        var state = imported.newState

        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(inboxId),
            expectedSeen = false,
            expectedFlagged = false,
        )

        val staleState = state
        artifacts.requireTrackedMailboxBeforeDispatch(targetMailboxId)
        state = applySingleEmailUpdate(
            owner = owner,
            accountId = accountId,
            emailId = emailId,
            ifInState = state,
            patch = buildJsonObject {
                put("mailboxIds/$targetMailboxId", true)
            },
            artifacts = artifacts,
        )
        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(inboxId, targetMailboxId),
            expectedSeen = false,
            expectedFlagged = false,
        )

        artifacts.requireTrackedEmailBeforeDispatch(emailId)
        artifacts.requireTrackedMailboxBeforeDispatch(targetMailboxId)
        val staleFailure = assertFailsWith<GateJmapException> {
            owner.call(
                methodName = "Email/set",
                arguments = buildEmailSetUpdateArguments(
                    accountId = accountId,
                    ifInState = staleState,
                    updates = linkedMapOf(
                        emailId to buildJsonObject {
                            put("mailboxIds/$targetMailboxId", JsonNull)
                        },
                    ),
                ),
                capabilities = MAIL_CAPABILITIES,
            )
        }
        assertEquals(
            GateEmailSetResponse.Conflict("stateMismatch"),
            requireGateEmailSetConflict(staleFailure),
        )
        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(inboxId, targetMailboxId),
            expectedSeen = false,
            expectedFlagged = false,
        )

        artifacts.requireTrackedMailboxBeforeDispatch(targetMailboxId)
        state = applySingleEmailUpdate(
            owner = owner,
            accountId = accountId,
            emailId = emailId,
            ifInState = state,
            patch = buildJsonObject {
                put("mailboxIds/$targetMailboxId", JsonNull)
            },
            artifacts = artifacts,
        )
        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(inboxId),
            expectedSeen = false,
            expectedFlagged = false,
        )

        artifacts.requireTrackedMailboxBeforeDispatch(targetMailboxId)
        state = applySingleEmailUpdate(
            owner = owner,
            accountId = accountId,
            emailId = emailId,
            ifInState = state,
            patch = buildJsonObject {
                put("mailboxIds/$targetMailboxId", true)
                put("mailboxIds/$inboxId", JsonNull)
            },
            artifacts = artifacts,
        )
        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(targetMailboxId),
            expectedSeen = false,
            expectedFlagged = false,
        )

        val absentEmailId = requireAbsentWellFormedEmailId(
            owner = owner,
            accountId = accountId,
            excludedId = emailId,
        )
        artifacts.requireTrackedEmailBeforeDispatch(emailId)
        val partial = parseGateEmailSetResponse(
            response = owner.call(
                methodName = "Email/set",
                arguments = buildEmailSetUpdateArguments(
                    accountId = accountId,
                    ifInState = state,
                    updates = linkedMapOf(
                        emailId to buildJsonObject {
                            put("keywords/\$seen", true)
                        },
                        absentEmailId to buildJsonObject {
                            put("keywords/\$seen", true)
                        },
                    ),
                ),
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedAccountId = accountId,
            requestedIds = linkedSetOf(emailId, absentEmailId),
        )
        assertEquals(state, partial.oldState)
        assertNotEquals(state, partial.newState)
        assertEquals(
            linkedMapOf(
                emailId to GateEmailSetObjectOutcome.Updated,
                absentEmailId to GateEmailSetObjectOutcome.NotUpdated("notFound"),
            ),
            partial.outcomes,
            "Email/set did not preserve typed per-object partial outcomes",
        )
        state = partial.newState
        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(targetMailboxId),
            expectedSeen = true,
            expectedFlagged = false,
        )

        state = applySingleEmailUpdate(
            owner = owner,
            accountId = accountId,
            emailId = emailId,
            ifInState = state,
            patch = buildJsonObject {
                put("keywords/\$seen", JsonNull)
            },
            artifacts = artifacts,
        )
        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(targetMailboxId),
            expectedSeen = false,
            expectedFlagged = false,
        )

        state = applySingleEmailUpdate(
            owner = owner,
            accountId = accountId,
            emailId = emailId,
            ifInState = state,
            patch = buildJsonObject {
                put("keywords/\$flagged", true)
            },
            artifacts = artifacts,
        )
        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(targetMailboxId),
            expectedSeen = false,
            expectedFlagged = true,
        )

        applySingleEmailUpdate(
            owner = owner,
            accountId = accountId,
            emailId = emailId,
            ifInState = state,
            patch = buildJsonObject {
                put("keywords/\$flagged", JsonNull)
            },
            artifacts = artifacts,
        )
        assertEmailShape(
            email = fetchEmail(owner, accountId, emailId),
            artifacts = artifacts,
            expectedMailboxIds = setOf(targetMailboxId),
            expectedSeen = false,
            expectedFlagged = false,
        )
    }

    private suspend fun createTargetMailbox(
        owner: GateJmapClient,
        accountId: String,
        artifacts: MutationArtifacts,
    ): String {
        val payload = artifacts.ledger.dispatchMailboxCreate {
            requireSingleJmapMethodPayload(
                response = owner.call(
                    methodName = "Mailbox/set",
                    arguments = buildJsonObject {
                        put("accountId", accountId)
                        put(
                            "create",
                            buildJsonObject {
                                put(
                                    MAILBOX_CREATION_ID,
                                    buildJsonObject {
                                        put("name", artifacts.mailboxName)
                                        put("parentId", JsonNull)
                                    },
                                )
                            },
                        )
                    },
                    capabilities = MAIL_CAPABILITIES,
                ),
                expectedMethod = "Mailbox/set",
            )
        }
        requireAccountId(payload, accountId, "Mailbox/set")
        requireEmptyObject(payload, "notCreated", "Mailbox/set")
        val mailboxId = requiredString(
            requiredObject(
                requiredObject(payload, "created")[MAILBOX_CREATION_ID],
            ),
            "id",
        )
        artifacts.recordMailboxId(mailboxId)
        return mailboxId
    }

    private suspend fun uploadMarkedMessage(
        owner: GateJmapClient,
        accountId: String,
        artifacts: MutationArtifacts,
    ): String {
        val message = artifacts.message()
        val payload = requireSingleJmapMethodPayload(
            response = owner.call(
                methodName = "Blob/upload",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                BLOB_CREATION_ID,
                                buildJsonObject {
                                    put(
                                        "data",
                                        buildJsonArray {
                                            add(
                                                buildJsonObject {
                                                    put("data:asText", message)
                                                },
                                            )
                                        },
                                    )
                                    put("type", "message/rfc822")
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Blob/upload",
        )
        requireAccountId(payload, accountId, "Blob/upload")
        requireEmptyObject(payload, "notCreated", "Blob/upload")
        val blob = requiredObject(
            requiredObject(payload, "created")[BLOB_CREATION_ID],
        )
        assertEquals("message/rfc822", requiredString(blob, "type"))
        assertEquals(
            message.encodeToByteArray().size.toLong(),
            requiredLong(blob, "size"),
        )
        return requiredString(blob, "id")
    }

    private suspend fun importMarkedEmail(
        owner: GateJmapClient,
        accountId: String,
        inboxId: String,
        blobId: String,
        artifacts: MutationArtifacts,
    ): ImportedEmail {
        check(inboxId.isNotBlank()) { "Email import source Mailbox ID is absent" }
        val payload = artifacts.ledger.dispatchEmailImport {
            requireSingleJmapMethodPayload(
                response = owner.call(
                    methodName = "Email/import",
                    arguments = buildJsonObject {
                        put("accountId", accountId)
                        put(
                            "emails",
                            buildJsonObject {
                                put(
                                    EMAIL_CREATION_ID,
                                    buildJsonObject {
                                        put("blobId", blobId)
                                        put(
                                            "mailboxIds",
                                            buildJsonObject {
                                                put(inboxId, true)
                                            },
                                        )
                                        put("keywords", buildJsonObject {})
                                        put("receivedAt", RECEIVED_AT.toString())
                                    },
                                )
                            },
                        )
                    },
                    capabilities = MAIL_CAPABILITIES,
                ),
                expectedMethod = "Email/import",
            )
        }
        requireAccountId(payload, accountId, "Email/import")
        requireEmptyObject(payload, "notCreated", "Email/import")
        val emailId = requiredString(
            requiredObject(
                requiredObject(payload, "created")[EMAIL_CREATION_ID],
            ),
            "id",
        )
        artifacts.recordEmailId(emailId)
        val oldState = requiredString(payload, "oldState")
        val newState = requiredString(payload, "newState")
        assertNotEquals(oldState, newState, "Email/import did not advance Email state")
        return ImportedEmail(emailId = emailId, newState = newState)
    }

    private suspend fun applySingleEmailUpdate(
        owner: GateJmapClient,
        accountId: String,
        emailId: String,
        ifInState: String,
        patch: JsonObject,
        artifacts: MutationArtifacts,
    ): String {
        artifacts.requireTrackedEmailBeforeDispatch(emailId)
        val applied = parseGateEmailSetResponse(
            response = owner.call(
                methodName = "Email/set",
                arguments = buildEmailSetUpdateArguments(
                    accountId = accountId,
                    ifInState = ifInState,
                    updates = linkedMapOf(emailId to patch),
                ),
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedAccountId = accountId,
            requestedIds = setOf(emailId),
        )
        assertEquals(ifInState, applied.oldState)
        assertNotEquals(ifInState, applied.newState)
        assertEquals(
            mapOf(emailId to GateEmailSetObjectOutcome.Updated),
            applied.outcomes,
            "Email/set did not confirm the exact requested Email",
        )
        return applied.newState
    }

    private suspend fun requireInboxId(
        owner: GateJmapClient,
        accountId: String,
    ): String {
        val payload = requireSingleJmapMethodPayload(
            response = owner.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "name", "role"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Mailbox/get",
        )
        requireAccountId(payload, accountId, "Mailbox/get")
        assertTrue(requiredArray(payload, "notFound").isEmpty())
        return assertNotNull(
            requiredArray(payload, "list")
                .map(::requiredObject)
                .singleOrNull { mailbox ->
                    mailbox["role"]?.jsonPrimitive?.contentOrNull == "inbox"
                }
                ?.let { mailbox -> requiredString(mailbox, "id") },
            "Mailbox/get did not return exactly one Inbox",
        )
    }

    private suspend fun fetchEmail(
        owner: GateJmapClient,
        accountId: String,
        emailId: String,
    ): JsonObject {
        val payload = requireSingleJmapMethodPayload(
            response = owner.call(
                methodName = "Email/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", strings(emailId))
                    put(
                        "properties",
                        strings(
                            "id",
                            "subject",
                            "mailboxIds",
                            "keywords",
                            "textBody",
                            "bodyValues",
                        ),
                    )
                    put("fetchTextBodyValues", true)
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Email/get",
        )
        requireAccountId(payload, accountId, "Email/get")
        assertTrue(requiredArray(payload, "notFound").isEmpty())
        val emails = requiredArray(payload, "list")
        assertEquals(1, emails.size, "Email/get returned the wrong object count")
        return requiredObject(emails.single()).also { email ->
            assertEquals(emailId, requiredString(email, "id"))
        }
    }

    private fun assertEmailShape(
        email: JsonObject,
        artifacts: MutationArtifacts,
        expectedMailboxIds: Set<String>,
        expectedSeen: Boolean,
        expectedFlagged: Boolean,
    ) {
        assertEquals(artifacts.subject, requiredString(email, "subject"))
        val mailboxIds = requiredBooleanMap(email, "mailboxIds")
        assertTrue(mailboxIds.values.all { it })
        assertEquals(expectedMailboxIds, mailboxIds.keys)
        val keywords = requiredBooleanMap(email, "keywords")
        assertTrue(keywords.values.all { it })
        assertEquals(expectedSeen, keywords["\$seen"] == true)
        assertEquals(expectedFlagged, keywords["\$flagged"] == true)
        val bodyValues = requiredObject(email, "bodyValues")
        assertTrue(
            bodyValues.values
                .map(::requiredObject)
                .map { body -> requiredString(body, "value") }
                .any { body -> artifacts.marker in body },
            "Email/get did not retain the exact mutation marker",
        )
    }

    private suspend fun requireAbsentWellFormedEmailId(
        owner: GateJmapClient,
        accountId: String,
        excludedId: String,
    ): String {
        for (candidate in WELL_FORMED_MISSING_EMAIL_IDS) {
            if (candidate == excludedId) continue
            val payload = requireSingleJmapMethodPayload(
                response = owner.call(
                    methodName = "Email/get",
                    arguments = buildJsonObject {
                        put("accountId", accountId)
                        put("ids", strings(candidate))
                        put("properties", strings("id"))
                    },
                    capabilities = MAIL_CAPABILITIES,
                ),
                expectedMethod = "Email/get",
            )
            requireAccountId(payload, accountId, "Email/get")
            if (
                requiredArray(payload, "list").isEmpty() &&
                requiredArray(payload, "notFound").map(::requiredString) ==
                listOf(candidate)
            ) {
                return candidate
            }
        }
        throw AssertionError("Gate could not establish a well-formed absent Email ID")
    }

    private suspend fun cleanupExactArtifacts(
        owner: GateJmapClient,
        accountId: String,
        artifacts: MutationArtifacts,
    ) {
        var cleanupFailure: Throwable? = null

        suspend fun attempt(block: suspend () -> Unit) {
            try {
                block()
            } catch (failure: Throwable) {
                cleanupFailure?.addSuppressed(failure)
                    ?: run { cleanupFailure = failure }
            }
        }

        if (artifacts.ledger.emailImportAttempted) {
            attempt {
                queryExactSubjectEmailIds(
                    owner = owner,
                    accountId = accountId,
                    ledger = artifacts.ledger,
                )
            }
        }
        if (artifacts.ledger.mailboxCreateAttempted) {
            attempt {
                queryExactMailboxIds(
                    owner = owner,
                    accountId = accountId,
                    ledger = artifacts.ledger,
                )
            }
        }

        artifacts.ledger.emailCleanupIds.toList().forEach { emailId ->
            attempt {
                artifacts.requireTrackedEmailBeforeDispatch(emailId)
                destroyExactObject(
                    owner = owner,
                    accountId = accountId,
                    methodName = "Email/set",
                    objectId = emailId,
                )
            }
        }
        artifacts.ledger.mailboxCleanupIds.toList().forEach { mailboxId ->
            attempt {
                artifacts.requireTrackedMailboxBeforeDispatch(mailboxId)
                destroyExactObject(
                    owner = owner,
                    accountId = accountId,
                    methodName = "Mailbox/set",
                    objectId = mailboxId,
                )
            }
        }

        if (artifacts.ledger.emailImportAttempted) {
            attempt {
                assertTrue(
                    queryExactSubjectEmailIds(
                        owner = owner,
                        accountId = accountId,
                        ledger = artifacts.ledger,
                    ).isEmpty(),
                    "Exact marker Email remained after cleanup",
                )
            }
        }
        if (artifacts.ledger.mailboxCreateAttempted) {
            attempt {
                assertTrue(
                    queryExactMailboxIds(
                        owner = owner,
                        accountId = accountId,
                        ledger = artifacts.ledger,
                    ).isEmpty(),
                    "Exact marker Mailbox remained after cleanup",
                )
            }
        }
        cleanupFailure?.let { throw it }
    }

    private suspend fun queryExactSubjectEmailIds(
        owner: GateJmapClient,
        accountId: String,
        ledger: GateMailArtifactLedger,
    ): Set<String> {
        val query = requireSingleJmapMethodPayload(
            response = owner.call(
                methodName = "Email/query",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "filter",
                        buildJsonObject {
                            put("subject", ledger.exactSubject)
                        },
                    )
                    put("sort", buildJsonArray {})
                    put("position", 0)
                    put("limit", CLEANUP_QUERY_LIMIT)
                    put("calculateTotal", true)
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Email/query",
        )
        requireAccountId(query, accountId, "Email/query")
        val ids = requiredArray(query, "ids").map(::requiredString)
        assertEquals(ids.size, ids.toSet().size, "Email/query returned duplicate IDs")
        assertEquals(0L, requiredLong(query, "position"))
        assertEquals(
            ids.size.toLong(),
            requiredLong(query, "total"),
            "Email/query marker reconciliation exceeded its exact bound",
        )
        if (ids.isEmpty()) return emptySet()

        val get = requireSingleJmapMethodPayload(
            response = owner.call(
                methodName = "Email/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonArray(ids.map(::JsonPrimitive)))
                    put("properties", strings("id", "subject", "messageId"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Email/get",
        )
        requireAccountId(get, accountId, "Email/get")
        val notFound = requiredArray(get, "notFound").map(::requiredString).toSet()
        val emails = requiredArray(get, "list").map(::requiredObject)
        val returnedIds = emails.map { email -> requiredString(email, "id") }
        assertEquals(
            ids.toSet(),
            returnedIds.toSet() + notFound,
            "Email/get did not account for each cleanup candidate",
        )
        return emails.mapNotNull { email ->
            val id = requiredString(email, "id")
            id.takeIf {
                ledger.reconcileEmailCandidate(
                    id = id,
                    subject = requiredString(email, "subject"),
                    messageIds = requiredArray(email, "messageId")
                        .map(::requiredString),
                )
            }
        }.toSet()
    }

    private suspend fun queryExactMailboxIds(
        owner: GateJmapClient,
        accountId: String,
        ledger: GateMailArtifactLedger,
    ): Set<String> {
        val payload = requireSingleJmapMethodPayload(
            response = owner.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "name"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Mailbox/get",
        )
        requireAccountId(payload, accountId, "Mailbox/get")
        assertTrue(requiredArray(payload, "notFound").isEmpty())
        return requiredArray(payload, "list")
            .map(::requiredObject)
            .mapNotNull { mailbox ->
                val id = requiredString(mailbox, "id")
                id.takeIf {
                    ledger.reconcileMailboxCandidate(
                        id = id,
                        name = requiredString(mailbox, "name"),
                    )
                }
            }
            .toSet()
    }

    private suspend fun destroyExactObject(
        owner: GateJmapClient,
        accountId: String,
        methodName: String,
        objectId: String,
    ) {
        val payload = requireSingleJmapMethodPayload(
            response = owner.call(
                methodName = methodName,
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("destroy", strings(objectId))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = methodName,
        )
        requireAccountId(payload, accountId, methodName)
        val destroyed = (payload["destroyed"] as? JsonArray)
            .orEmpty()
            .map(::requiredString)
        val notDestroyed = (payload["notDestroyed"] as? JsonObject).orEmpty()
        assertFalse(
            objectId in destroyed && objectId in notDestroyed,
            "$methodName cleanup returned contradictory outcomes",
        )
        if (destroyed == listOf(objectId) && notDestroyed.isEmpty()) return
        assertTrue(destroyed.isEmpty(), "$methodName cleanup destroyed another object")
        assertEquals(setOf(objectId), notDestroyed.keys)
        assertEquals(
            "notFound",
            requiredString(requiredObject(notDestroyed[objectId]), "type"),
            "$methodName cleanup neither deleted nor proved the exact object absent",
        )
    }

    private fun requirePrimaryAccount(session: GateJmapSession): String {
        assertEquals(EXPECTED_API_URL, session.apiUrl)
        assertEquals(GateBootstrap.FIRST_USER_ADDRESS, session.username)
        return assertNotNull(
            session.primaryAccountId,
            "Ordinary JMAP Session omitted its primary Account",
        ).also { accountId ->
            assertTrue(accountId.isNotBlank())
        }
    }

    private fun requireAccountId(
        payload: JsonObject,
        expectedAccountId: String,
        methodName: String,
    ) {
        assertEquals(
            expectedAccountId,
            requiredString(payload, "accountId"),
            "$methodName returned another Account",
        )
    }

    private fun requireEmptyObject(
        payload: JsonObject,
        property: String,
        methodName: String,
    ) {
        assertTrue(
            (payload[property] as? JsonObject).orEmpty().isEmpty(),
            "$methodName returned $property",
        )
    }

    private fun requiredObject(value: JsonElement?): JsonObject =
        value as? JsonObject
            ?: throw AssertionError("JMAP response object was absent or malformed")

    private fun requiredObject(value: JsonObject, property: String): JsonObject =
        requiredObject(value[property])

    private fun requiredArray(value: JsonObject, property: String): JsonArray =
        value[property] as? JsonArray
            ?: throw AssertionError("$property was absent or malformed")

    private fun requiredString(value: JsonElement): String {
        val primitive = value as? JsonPrimitive
        assertNotNull(primitive, "JMAP response string was malformed")
        assertTrue(primitive.isString, "JMAP response value was not a string")
        return primitive.content
    }

    private fun requiredString(value: JsonObject, property: String): String =
        value[property]?.let(::requiredString)
            ?: throw AssertionError("$property was absent")

    private fun requiredLong(value: JsonObject, property: String): Long =
        value[property]?.jsonPrimitive?.longOrNull
            ?: throw AssertionError("$property was absent or malformed")

    private fun requiredBooleanMap(
        value: JsonObject,
        property: String,
    ): Map<String, Boolean> =
        requiredObject(value, property).mapValues { (_, item) ->
            item.jsonPrimitive.booleanOrNull
                ?: throw AssertionError("$property contained a malformed value")
        }

    private fun strings(vararg values: String): JsonArray =
        buildJsonArray {
            values.forEach { value -> add(JsonPrimitive(value)) }
        }

    private fun dashboardProjectRoot(): Path {
        val working = Paths.get(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val candidate = if (working.fileName?.toString() == "dashboard-server") {
            assertNotNull(working.parent)
        } else {
            working
        }
        assertEquals(
            "debug-dashboard",
            candidate.fileName?.toString(),
            "Live gate must run from debug-dashboard or dashboard-server",
        )
        assertTrue(
            Files.isRegularFile(candidate.resolve("project.yaml")),
            "Live gate project root is missing project.yaml",
        )
        return candidate.toRealPath()
    }

    private data class ImportedEmail(
        val emailId: String,
        val newState: String,
    )

    private class MutationArtifacts(
        val marker: String,
    ) {
        val subject = "Gate 0B mail mutation $marker"
        val mailboxName = "Gate 0B mail mutation $marker"
        val messageId = "<gate0b-mail-mutation-$marker@local.test>"
        val ledger = GateMailArtifactLedger(
            exactSubject = subject,
            exactMessageId = messageId,
            exactMailboxNames = setOf(mailboxName),
        )

        fun recordMailboxId(mailboxId: String) {
            ledger.recordMailboxId(mailboxId)
        }

        fun recordEmailId(emailId: String) {
            ledger.recordEmailId(emailId)
        }

        fun requireTrackedMailboxBeforeDispatch(mailboxId: String) {
            check(mailboxId in ledger.mailboxCleanupIds) {
                "Mailbox dispatch used an untracked ID"
            }
        }

        fun requireTrackedEmailBeforeDispatch(emailId: String) {
            check(emailId in ledger.emailCleanupIds) {
                "Email dispatch used an untracked ID"
            }
        }

        fun message(): String = buildString {
            append("From: gate-sender@local.test\r\n")
            append("To: ${GateBootstrap.FIRST_USER_ADDRESS}\r\n")
            append("Date: Wed, 05 Aug 2026 12:00:00 +0000\r\n")
            append("Subject: $subject\r\n")
            append("Message-ID: $messageId\r\n")
            append("MIME-Version: 1.0\r\n")
            append("Content-Type: text/plain; charset=UTF-8\r\n")
            append("\r\n")
            append("Gate 0B mail mutation body marker $marker\r\n")
        }
    }

    private companion object {
        val EXPECTED_API_URL: URI = URI("http://127.0.0.1:18443/jmap/")
        val RECEIVED_AT: Instant = Instant.parse("2026-08-05T12:00:00Z")
        val MAIL_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.MAIL,
            GateJmapCapability.BLOB,
        )
        val WELL_FORMED_MISSING_EMAIL_IDS = listOf(
            "p333333333333p333333333333",
            "a",
        )
        const val MAILBOX_CREATION_ID = "gate-mail-mutation-mailbox"
        const val BLOB_CREATION_ID = "gate-mail-mutation-blob"
        const val EMAIL_CREATION_ID = "gate-mail-mutation-email"
        const val CLEANUP_QUERY_LIMIT = 100
    }
}
