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
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class StalwartRegistryRoutingDeletionLiveTest {
    @Test
    fun provesRegistryRoutingAndPositiveDataBearingAccountDeletion() = runBlocking {
        val environment = System.getenv()
        val projectRoot = dashboardProjectRoot()
        val live = StalwartLiveTestEnvironment.load(
            environment = environment,
            projectRoot = projectRoot,
        )
        live.awaitReady()
        StalwartDockerMountAudit.assertReviewedLiveMounts(projectRoot)

        val marker = UUID.randomUUID().toString().replace("-", "")
        val localPart = "gate-registry-$marker"
        val address = "$localPart@local.test"
        val password = "Gate0b-$marker-Aa9!".toCharArray()
        try {
            StalwartGateSecretFiles.readFixtureSecrets(
                projectRoot = projectRoot,
                environment = environment,
            ).use { fixture ->
                KtorGateHttpTransport(followRedirects = false).use { transport ->
                    GateJmapClient(
                        baseUrl = live.baseUrl,
                        credential = GateCredential.bearer(fixture.managementApiKey),
                        transport = transport,
                    ).use { manager ->
                        val managementSession = manager.discoverSession()
                        assertEquals(
                            fixture.managementAccountId,
                            managementSession.primaryAccountId,
                        )
                        assertEquals(
                            GateBootstrap.MANAGEMENT_ADDRESS,
                            managementSession.username,
                        )
                        assertEquals(
                            EXPECTED_API_URL,
                            managementSession.apiUrl,
                        )

                        val baseline = collectGateRegistryQuerySnapshot(
                            registry = manager,
                            objectType = "Account",
                            accountId = fixture.managementAccountId,
                            pageSize = REGISTRY_PAGE_SIZE,
                            maximumRecords = MAXIMUM_ACCOUNT_RECORDS,
                            maximumPages = MAXIMUM_ACCOUNT_PAGES,
                        )
                        val baselineIds = baseline.ids.toSet()
                        assertEquals(baseline.ids.size, baselineIds.size)
                        val domainId = resolveLocalDomainId(
                            live = live,
                            transport = transport,
                            manager = manager,
                            fixture = fixture,
                        )
                        val ledger = GateOwnedAccountLedger(
                            localPart = localPart,
                            domainId = domainId,
                            baselineAccountIds = baselineIds,
                        )

                        var primaryFailure: Throwable? = null
                        try {
                            val createResponse = ledger.dispatchCreate {
                                manager.registryCreate(
                                    objectType = "Account",
                                    creationId = ACCOUNT_CREATION_ID,
                                    value = accountCreateValue(
                                        localPart = localPart,
                                        domainId = domainId,
                                        password = password,
                                    ),
                                    accountId = fixture.managementAccountId,
                                )
                            }
                            val accountId = requireCreatedObject(
                                response = createResponse,
                                expectedMethod = "x:Account/set",
                                expectedAccountId = fixture.managementAccountId,
                                creationId = ACCOUNT_CREATION_ID,
                            ).requiredSafeId("id")
                            ledger.recordCreatedId(accountId)

                            val projection = requireNotNull(
                                fetchRegistryObject(
                                    manager = manager,
                                    managementAccountId = fixture.managementAccountId,
                                    objectType = "Account",
                                    objectId = accountId,
                                ),
                            ) { "Created Account was immediately absent" }
                            assertTrue(ledger.reconcileCandidate(projection))
                            assertAccountProjection(
                                projection = projection,
                                expectedId = accountId,
                                expectedLocalPart = localPart,
                                expectedDomainId = domainId,
                                plaintextPassword = password,
                            )

                            GateJmapClient(
                                baseUrl = live.baseUrl,
                                credential = GateCredential.basic(address, password),
                                transport = transport,
                            ).use { accountClient ->
                                val accountSession = accountClient.discoverSession()
                                assertEquals(address, accountSession.username)
                                assertEquals(accountId, accountSession.primaryAccountId)
                                assertEquals(
                                    EXPECTED_API_URL,
                                    accountSession.apiUrl,
                                )

                                val smtpMessage = RouteMessage(
                                    subject = "Gate registry SMTP $marker",
                                    messageId = "<gate-registry-smtp-$marker@local.test>",
                                    body = "mail-sandbox Gate 0B SMTP routing $marker",
                                )
                                assertTrue(
                                    queryExactSubjectIds(
                                        client = accountClient,
                                        accountId = accountId,
                                        subject = smtpMessage.subject,
                                    ).isEmpty(),
                                    "SMTP marker existed before dispatch",
                                )
                                sendSmtpMessage(
                                    username = address,
                                    password = password,
                                    sender = address,
                                    recipient = address,
                                    message = smtpMessage,
                                )
                                val smtpEmailId = awaitExactDelivery(
                                    client = accountClient,
                                    accountId = accountId,
                                    message = smtpMessage,
                                    excludedIds = emptySet(),
                                )
                                requireExactEmail(
                                    client = accountClient,
                                    accountId = accountId,
                                    emailId = smtpEmailId,
                                    message = smtpMessage,
                                )

                                val submissionMessage = RouteMessage(
                                    subject = "Gate registry JMAP $marker",
                                    messageId = "<gate-registry-jmap-$marker@local.test>",
                                    body = "mail-sandbox Gate 0B JMAP submission $marker",
                                )
                                assertTrue(
                                    queryExactSubjectIds(
                                        client = accountClient,
                                        accountId = accountId,
                                        subject = submissionMessage.subject,
                                    ).isEmpty(),
                                    "JMAP marker existed before dispatch",
                                )
                                val sourceEmailId = submitSelfMessage(
                                    client = accountClient,
                                    accountId = accountId,
                                    address = address,
                                    message = submissionMessage,
                                )
                                val jmapEmailId = awaitExactDelivery(
                                    client = accountClient,
                                    accountId = accountId,
                                    message = submissionMessage,
                                    excludedIds = setOf(sourceEmailId),
                                )
                                requireExactEmail(
                                    client = accountClient,
                                    accountId = accountId,
                                    emailId = jmapEmailId,
                                    message = submissionMessage,
                                )
                                assertTrue(smtpEmailId != jmapEmailId)
                            }

                            val currentProjection = requireNotNull(
                                fetchRegistryObject(
                                    manager = manager,
                                    managementAccountId = fixture.managementAccountId,
                                    objectType = "Account",
                                    objectId = accountId,
                                ),
                            ) { "Data-bearing Account disappeared before deletion" }
                            ledger.requireSafeToDestroy(accountId, currentProjection)
                            requireDestroyedObject(
                                response = manager.registryDestroy(
                                    objectType = "Account",
                                    objectId = accountId,
                                    accountId = fixture.managementAccountId,
                                ),
                                expectedMethod = "x:Account/set",
                                expectedAccountId = fixture.managementAccountId,
                                objectId = accountId,
                            )
                            assertEquals(
                                null,
                                fetchRegistryObject(
                                    manager = manager,
                                    managementAccountId = fixture.managementAccountId,
                                    objectType = "Account",
                                    objectId = accountId,
                                ),
                                "Account/get did not return the destroyed Account in notFound",
                            )
                            requireBaselineRestored(
                                manager = manager,
                                managementAccountId = fixture.managementAccountId,
                                baselineIds = baselineIds,
                            )
                            assertJmapAuthenticationRejected(
                                live = live,
                                transport = transport,
                                username = address,
                                password = password,
                            )
                        } catch (failure: Throwable) {
                            primaryFailure = failure
                            throw failure
                        } finally {
                            var cleanupFailure: Throwable? = null
                            withContext(NonCancellable) {
                                try {
                                    cleanupExactOwnedAccount(
                                        manager = manager,
                                        managementAccountId = fixture.managementAccountId,
                                        baselineIds = baselineIds,
                                        ledger = ledger,
                                    )
                                } catch (failure: Throwable) {
                                    cleanupFailure = failure
                                }
                            }
                            cleanupFailure?.let { failure ->
                                primaryFailure?.addSuppressed(failure) ?: throw failure
                            }
                        }
                    }
                }
            }
        } finally {
            password.fill('\u0000')
        }
    }

    private suspend fun resolveLocalDomainId(
        live: StalwartLiveTestEnvironment,
        transport: GateHttpTransport,
        manager: GateJmapClient,
        fixture: GateFixtureSecrets,
    ): String {
        val ordinaryAccountId = GateJmapClient(
            baseUrl = live.baseUrl,
            credential = GateCredential.basic(
                username = GateBootstrap.FIRST_USER_ADDRESS,
                secret = fixture.firstUserPassword,
            ),
            transport = transport,
        ).use { client ->
            val session = client.discoverSession()
            assertEquals(GateBootstrap.FIRST_USER_ADDRESS, session.username)
            assertNotNull(session.primaryAccountId)
        }
        val account = requireNotNull(
            fetchRegistryObject(
                manager = manager,
                managementAccountId = fixture.managementAccountId,
                objectType = "Account",
                objectId = ordinaryAccountId,
            ),
        ) { "Fixture ordinary Account was absent" }
        val domainId = account.requiredSafeId("domainId")
        val domain = requireNotNull(
            fetchRegistryObject(
                manager = manager,
                managementAccountId = fixture.managementAccountId,
                objectType = "Domain",
                objectId = domainId,
            ),
        ) { "Fixture local.test Domain was absent" }
        assertEquals(domainId, domain.requiredSafeId("id"))
        assertEquals("local.test", domain.requiredString("name"))
        return domainId
    }

    private fun accountCreateValue(
        localPart: String,
        domainId: String,
        password: CharArray,
    ): JsonObject = buildJsonObject {
        put("@type", "User")
        put("name", localPart)
        put("domainId", domainId)
        put(
            "credentials",
            buildJsonObject {
                put(
                    "0",
                    buildJsonObject {
                        put("@type", "Password")
                        put("secret", password.concatToString())
                        put("allowedIps", buildJsonObject {})
                    },
                )
            },
        )
        put("roles", typed("User"))
        put("permissions", replacePermissions(DASHBOARD_ACCOUNT_PERMISSIONS))
    }

    private fun assertAccountProjection(
        projection: JsonObject,
        expectedId: String,
        expectedLocalPart: String,
        expectedDomainId: String,
        plaintextPassword: CharArray,
    ) {
        assertEquals(expectedId, projection.requiredSafeId("id"))
        assertEquals("User", projection.requiredString("@type"))
        assertEquals(expectedLocalPart, projection.requiredString("name"))
        assertEquals(expectedDomainId, projection.requiredSafeId("domainId"))
        assertEquals(
            setOf("@type"),
            projection.requiredObject("roles").keys,
        )
        assertEquals(
            "User",
            projection.requiredObject("roles").requiredString("@type"),
        )
        val permissions = projection.requiredObject("permissions")
        assertEquals("Replace", permissions.requiredString("@type"))
        val enabled = permissions.requiredObject("enabledPermissions")
        assertEquals(DASHBOARD_ACCOUNT_PERMISSIONS, enabled.keys)
        assertTrue(enabled.values.all { value -> value.jsonPrimitive.booleanOrNull == true })
        assertTrue(permissions.requiredObject("disabledPermissions").isEmpty())

        val credentials = projection.requiredObject("credentials")
        assertEquals(1, credentials.size, "Created Account must have one credential")
        val passwordDescriptor = credentials.values.single() as? JsonObject
        assertNotNull(passwordDescriptor, "Password credential projection is malformed")
        assertEquals("Password", passwordDescriptor.requiredString("@type"))
        passwordDescriptor["secret"]?.let { secret ->
            val mask = secret.requiredStringValue("Password secret projection")
            assertTrue(
                mask.isNotEmpty() && mask.all { it == '*' },
                "Password credential projection was not masked",
            )
        }
        val plaintext = plaintextPassword.concatToString()
        assertFalse(
            projection.containsStringFragment(plaintext),
            "Registry projection exposed the Account plaintext password",
        )
    }

    private suspend fun submitSelfMessage(
        client: GateJmapClient,
        accountId: String,
        address: String,
        message: RouteMessage,
    ): String {
        val mailboxId = findDraftMailbox(client, accountId)
        val identityId = findIdentity(client, accountId, address)
        val rawMessage = message.asRfc5322(address, address)
        val blob = requireCreatedObject(
            response = client.call(
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
                                            add(buildJsonObject { put("data:asText", rawMessage) })
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
            expectedAccountId = accountId,
            creationId = BLOB_CREATION_ID,
        )
        assertEquals("message/rfc822", blob.requiredString("type"))
        val blobId = blob.requiredSafeId("id")

        val imported = requireCreatedObject(
            response = client.call(
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
                                        buildJsonObject { put(mailboxId, true) },
                                    )
                                    put(
                                        "keywords",
                                        buildJsonObject {
                                            put("\$draft", true)
                                            put("\$seen", true)
                                        },
                                    )
                                    put("receivedAt", Instant.now().toString())
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Email/import",
            expectedAccountId = accountId,
            creationId = EMAIL_CREATION_ID,
        )
        val sourceEmailId = imported.requiredSafeId("id")
        assertEquals(
            setOf(sourceEmailId),
            queryExactSubjectIds(client, accountId, message.subject),
            "Imported JMAP source Email was not the unique marker",
        )

        val submission = requireCreatedObject(
            response = client.call(
                methodName = "EmailSubmission/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                SUBMISSION_CREATION_ID,
                                buildJsonObject {
                                    put("emailId", sourceEmailId)
                                    put("identityId", identityId)
                                    put(
                                        "envelope",
                                        buildJsonObject {
                                            put(
                                                "mailFrom",
                                                buildJsonObject { put("email", address) },
                                            )
                                            put(
                                                "rcptTo",
                                                buildJsonArray {
                                                    add(
                                                        buildJsonObject {
                                                            put("email", address)
                                                        },
                                                    )
                                                },
                                            )
                                        },
                                    )
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "EmailSubmission/set",
            expectedAccountId = accountId,
            creationId = SUBMISSION_CREATION_ID,
        )
        assertTrue(submission.requiredSafeId("id").isNotBlank())
        return sourceEmailId
    }

    private suspend fun findDraftMailbox(
        client: GateJmapClient,
        accountId: String,
    ): String {
        val payload = requireSingleJmapMethodPayload(
            response = client.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "role"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Mailbox/get",
        )
        assertEquals(accountId, payload.requiredSafeId("accountId"))
        assertTrue(payload.requiredArray("notFound").isEmpty())
        val candidates = payload.requiredArray("list")
            .map { it.requiredObjectValue("Mailbox/get result") }
            .mapNotNull { mailbox ->
                val role = mailbox.optionalString("role")
                if (role == "drafts" || role == "inbox") {
                    role to mailbox.requiredSafeId("id")
                } else {
                    null
                }
            }
        return candidates.firstOrNull { it.first == "drafts" }?.second
            ?: candidates.firstOrNull { it.first == "inbox" }?.second
            ?: throw AssertionError("Created Account has no drafts or inbox Mailbox")
    }

    private suspend fun findIdentity(
        client: GateJmapClient,
        accountId: String,
        address: String,
    ): String {
        val payload = requireSingleJmapMethodPayload(
            response = client.call(
                methodName = "Identity/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "email"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Identity/get",
        )
        assertEquals(accountId, payload.requiredSafeId("accountId"))
        assertTrue(payload.requiredArray("notFound").isEmpty())
        val matches = payload.requiredArray("list")
            .map { it.requiredObjectValue("Identity/get result") }
            .filter { it.requiredString("email") == address }
        assertEquals(1, matches.size, "Created Account Identity was not unique")
        return matches.single().requiredSafeId("id")
    }

    private suspend fun queryExactSubjectIds(
        client: GateJmapClient,
        accountId: String,
        subject: String,
    ): Set<String> {
        val payload = requireSingleJmapMethodPayload(
            response = client.call(
                methodName = "Email/query",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("filter", buildJsonObject { put("subject", subject) })
                    put("sort", buildJsonArray {})
                    put("position", 0)
                    put("limit", MAXIMUM_MARKER_RESULTS)
                    put("calculateTotal", true)
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Email/query",
        )
        assertEquals(accountId, payload.requiredSafeId("accountId"))
        assertEquals(0, payload.requiredInt("position"))
        val ids = payload.requiredArray("ids").map {
            it.requiredStringValue("Email/query ID").also { id ->
                assertTrue(id.isSafeGateRegistryId(), "Email/query returned an unsafe ID")
            }
        }
        assertEquals(ids.size, ids.toSet().size, "Email/query returned duplicate IDs")
        assertEquals(ids.size, payload.requiredInt("total"), "Email/query result was truncated")
        assertTrue(ids.size <= MAXIMUM_MARKER_RESULTS)
        return ids.toSet()
    }

    private suspend fun awaitExactDelivery(
        client: GateJmapClient,
        accountId: String,
        message: RouteMessage,
        excludedIds: Set<String>,
    ): String {
        repeat(DELIVERY_ATTEMPTS) { attempt ->
            val ids = queryExactSubjectIds(client, accountId, message.subject)
            assertTrue(
                ids.containsAll(excludedIds),
                "A source marker Email disappeared before delivery",
            )
            val delivered = ids - excludedIds
            assertTrue(delivered.size <= 1, "Message route produced duplicate deliveries")
            if (delivered.size == 1) return delivered.single()
            if (attempt + 1 < DELIVERY_ATTEMPTS) delay(DELIVERY_DELAY_MILLIS)
        }
        throw AssertionError("Message did not arrive within the bounded delivery window")
    }

    private suspend fun requireExactEmail(
        client: GateJmapClient,
        accountId: String,
        emailId: String,
        message: RouteMessage,
    ) {
        val payload = requireSingleJmapMethodPayload(
            response = client.call(
                methodName = "Email/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", strings(emailId))
                    put("properties", strings("id", "subject", "messageId"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            expectedMethod = "Email/get",
        )
        assertEquals(accountId, payload.requiredSafeId("accountId"))
        assertTrue(payload.requiredArray("notFound").isEmpty())
        val values = payload.requiredArray("list")
        assertEquals(1, values.size, "Email/get returned the wrong object count")
        val email = values.single().requiredObjectValue("Email/get result")
        assertEquals(emailId, email.requiredSafeId("id"))
        assertEquals(message.subject, email.requiredString("subject"))
        assertEquals(
            listOf(message.bareMessageId),
            email.requiredArray("messageId").map {
                it.requiredStringValue("Email Message-ID")
            },
        )
    }

    private suspend fun fetchRegistryObject(
        manager: GateJmapClient,
        managementAccountId: String,
        objectType: String,
        objectId: String,
    ): JsonObject? {
        val payload = requireSingleJmapMethodPayload(
            response = manager.registryGet(
                objectType = objectType,
                ids = listOf(objectId),
                accountId = managementAccountId,
            ),
            expectedMethod = "x:$objectType/get",
        )
        assertEquals(managementAccountId, payload.requiredSafeId("accountId"))
        val values = payload.requiredArray("list")
        val notFound = payload.requiredArray("notFound").map {
            it.requiredStringValue("Registry notFound ID")
        }
        return when {
            values.size == 1 && notFound.isEmpty() ->
                values.single().requiredObjectValue("Registry get result").also {
                    assertEquals(objectId, it.requiredSafeId("id"))
                }

            values.isEmpty() && notFound == listOf(objectId) -> null
            else -> throw AssertionError("Registry get returned an ambiguous object result")
        }
    }

    private fun requireCreatedObject(
        response: JsonObject,
        expectedMethod: String,
        expectedAccountId: String,
        creationId: String,
    ): JsonObject {
        val payload = requireSingleJmapMethodPayload(response, expectedMethod)
        assertEquals(expectedAccountId, payload.requiredSafeId("accountId"))
        val notCreated = payload.optionalObject("notCreated")
        assertTrue(
            notCreated.isEmpty(),
            "Registry create was rejected: ${notCreated.safeSetErrorSummary()}",
        )
        val created = payload.requiredObject("created")
        assertEquals(setOf(creationId), created.keys)
        return created.getValue(creationId).requiredObjectValue("created object")
    }

    private fun requireDestroyedObject(
        response: JsonObject,
        expectedMethod: String,
        expectedAccountId: String,
        objectId: String,
    ) {
        val payload = requireSingleJmapMethodPayload(response, expectedMethod)
        assertEquals(expectedAccountId, payload.requiredSafeId("accountId"))
        assertTrue(payload.optionalObject("notDestroyed").isEmpty())
        assertEquals(
            listOf(objectId),
            payload.requiredArray("destroyed").map {
                it.requiredStringValue("destroyed object ID")
            },
        )
    }

    private suspend fun requireBaselineRestored(
        manager: GateJmapClient,
        managementAccountId: String,
        baselineIds: Set<String>,
    ) {
        val current = collectGateRegistryQuerySnapshot(
            registry = manager,
            objectType = "Account",
            accountId = managementAccountId,
            pageSize = REGISTRY_PAGE_SIZE,
            maximumRecords = MAXIMUM_ACCOUNT_RECORDS,
            maximumPages = MAXIMUM_ACCOUNT_PAGES,
        )
        assertEquals(current.ids.size, current.ids.toSet().size)
        assertEquals(baselineIds, current.ids.toSet(), "Account inventory was not restored")
    }

    private suspend fun cleanupExactOwnedAccount(
        manager: GateJmapClient,
        managementAccountId: String,
        baselineIds: Set<String>,
        ledger: GateOwnedAccountLedger,
    ) {
        if (!ledger.createAttempted) return
        val current = collectGateRegistryQuerySnapshot(
            registry = manager,
            objectType = "Account",
            accountId = managementAccountId,
            pageSize = REGISTRY_PAGE_SIZE,
            maximumRecords = MAXIMUM_ACCOUNT_RECORDS,
            maximumPages = MAXIMUM_ACCOUNT_PAGES,
        )
        val candidateIds = current.ids.toSet() - baselineIds
        require(candidateIds.size <= MAXIMUM_CLEANUP_CANDIDATES) {
            "Account cleanup candidate bound was exceeded"
        }
        candidateIds.forEach { candidateId ->
            val projection = requireNotNull(
                fetchRegistryObject(
                    manager = manager,
                    managementAccountId = managementAccountId,
                    objectType = "Account",
                    objectId = candidateId,
                ),
            ) { "Account cleanup candidate disappeared during reconciliation" }
            ledger.reconcileCandidate(projection)
        }
        ledger.cleanupIds.forEach { cleanupId ->
            val projection = fetchRegistryObject(
                manager = manager,
                managementAccountId = managementAccountId,
                objectType = "Account",
                objectId = cleanupId,
            ) ?: return@forEach
            ledger.requireSafeToDestroy(cleanupId, projection)
            requireDestroyedObject(
                response = manager.registryDestroy(
                    objectType = "Account",
                    objectId = cleanupId,
                    accountId = managementAccountId,
                ),
                expectedMethod = "x:Account/set",
                expectedAccountId = managementAccountId,
                objectId = cleanupId,
            )
        }
        requireBaselineRestored(manager, managementAccountId, baselineIds)
    }

    private suspend fun assertJmapAuthenticationRejected(
        live: StalwartLiveTestEnvironment,
        transport: GateHttpTransport,
        username: String,
        password: CharArray,
    ) {
        val failure = GateJmapClient(
            baseUrl = live.baseUrl,
            credential = GateCredential.basic(username, password),
            transport = transport,
        ).use { client ->
            assertFailsWith<GateJmapException> { client.discoverSession() }
        }
        val status = (failure.kind as? GateJmapFailure.HttpStatus)?.status
        assertTrue(
            status == 401 || status == 403,
            "Destroyed Account JMAP authentication failed for an unrelated reason",
        )
    }

    private suspend fun sendSmtpMessage(
        username: String,
        password: CharArray,
        sender: String,
        recipient: String,
        message: RouteMessage,
    ) {
        val outcome = withContext(Dispatchers.IO) {
            GateSmtpClient.disposableGate().use { client ->
                client.send(
                    username = username,
                    secret = password,
                    envelopeFrom = sender,
                    envelopeRecipient = recipient,
                    rawMessage = message.asRfc5322(sender, recipient),
                )
            }
        }
        val accepted = assertIs<GateSmtpDeliveryOutcome.Accepted>(
            outcome,
            "SMTP DATA route was rejected",
        )
        assertTrue(accepted.recipient.code == 250 || accepted.recipient.code == 251)
        assertEquals(250, accepted.queuedCode, "SMTP DATA was not queued")
        accepted.queuedEnhancedStatus?.let { status ->
            assertTrue(status.startsWith("2."), "SMTP DATA returned a non-success status")
        }
    }

    private fun dashboardProjectRoot(): Path {
        val working = Paths.get(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val candidate = if (working.fileName?.toString() == "dashboard-server") {
            requireNotNull(working.parent)
        } else {
            working
        }
        require(
            candidate.fileName?.toString() == "debug-dashboard" &&
                Files.isRegularFile(candidate.resolve("project.yaml")),
        ) {
            "Registry routing live gate must run from debug-dashboard or dashboard-server"
        }
        return candidate.toRealPath()
    }

    private fun typed(type: String): JsonObject =
        buildJsonObject { put("@type", type) }

    private fun replacePermissions(values: Set<String>): JsonObject = buildJsonObject {
        put("@type", "Replace")
        put(
            "enabledPermissions",
            buildJsonObject {
                values.forEach { permission -> put(permission, true) }
            },
        )
        put("disabledPermissions", buildJsonObject {})
    }

    private fun strings(vararg values: String): JsonArray =
        JsonArray(values.map(::JsonPrimitive))

    private fun JsonObject.requiredObject(property: String): JsonObject =
        this[property] as? JsonObject
            ?: throw AssertionError("$property is absent or malformed")

    private fun JsonObject.optionalObject(property: String): JsonObject =
        when (val value = this[property]) {
            null, JsonNull -> JsonObject(emptyMap())
            is JsonObject -> value
            else -> throw AssertionError("$property is malformed")
        }

    private fun JsonObject.safeSetErrorSummary(): String =
        entries.joinToString(prefix = "[", postfix = "]") { (creationId, value) ->
            val error = value as? JsonObject
            val type = error?.optionalString("type") ?: "unknown"
            val properties = (error?.get("properties") as? JsonArray)
                .orEmpty()
                .mapNotNull { property ->
                    (property as? JsonPrimitive)
                        ?.takeIf { primitive -> primitive.isString }
                        ?.content
                }
            "creationId=$creationId,type=$type,properties=$properties"
        }

    private fun JsonObject.requiredArray(property: String): JsonArray =
        this[property] as? JsonArray
            ?: throw AssertionError("$property is absent or malformed")

    private fun JsonObject.requiredString(property: String): String =
        this[property]?.requiredStringValue(property)
            ?: throw AssertionError("$property is absent")

    private fun JsonObject.optionalString(property: String): String? =
        when (val value = this[property]) {
            null, JsonNull -> null
            else -> value.requiredStringValue(property)
        }

    private fun JsonObject.requiredSafeId(property: String): String =
        requiredString(property).also { value ->
            assertTrue(value.isSafeGateRegistryId(), "$property is not a safe Gate ID")
        }

    private fun JsonObject.requiredInt(property: String): Int {
        val value = this[property] as? JsonPrimitive
            ?: throw AssertionError("$property is absent or malformed")
        assertFalse(value.isString, "$property must be numeric")
        return value.intOrNull ?: throw AssertionError("$property is not an integer")
    }

    private fun JsonElement.requiredObjectValue(label: String): JsonObject =
        this as? JsonObject ?: throw AssertionError("$label is malformed")

    private fun JsonElement.requiredStringValue(label: String): String {
        val primitive = this as? JsonPrimitive
            ?: throw AssertionError("$label is malformed")
        assertTrue(primitive.isString, "$label is not a string")
        return primitive.content.also { value ->
            assertTrue(
                value.isBoundedGateRegistryOpaqueText() && '\u0000' !in value,
                "$label is outside the Gate text bound",
            )
        }
    }

    private fun JsonElement.containsStringFragment(fragment: String): Boolean =
        when (this) {
            is JsonArray -> any { it.containsStringFragment(fragment) }
            is JsonObject -> entries.any { (name, value) ->
                fragment in name || value.containsStringFragment(fragment)
            }
            is JsonPrimitive -> isString && fragment in content
        }

    private data class RouteMessage(
        val subject: String,
        val messageId: String,
        val body: String,
    ) {
        val bareMessageId: String = messageId.removePrefix("<").removeSuffix(">")

        init {
            require(messageId == "<$bareMessageId>")
            require(bareMessageId.endsWith("@local.test"))
            require(subject.none { it == '\r' || it == '\n' })
            require(body.none { it == '\r' || it == '\n' })
        }

        fun asRfc5322(sender: String, recipient: String): String = buildString {
            append("From: <")
            append(sender)
            append(">\r\nTo: <")
            append(recipient)
            append(">\r\nDate: Wed, 05 Aug 2026 12:00:00 +0000\r\n")
            append("Message-ID: ")
            append(messageId)
            append("\r\nSubject: ")
            append(subject)
            append("\r\nMIME-Version: 1.0\r\n")
            append("Content-Type: text/plain; charset=UTF-8\r\n")
            append("Content-Transfer-Encoding: 7bit\r\n\r\n")
            append(body)
            append("\r\n")
        }
    }

    private companion object {
        val EXPECTED_API_URL: URI = StalwartEndpointProfile.GATE_FIXTURE.apiUrl
        val MAIL_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.MAIL,
            GateJmapCapability.SUBMISSION,
            GateJmapCapability.BLOB,
        )
        const val ACCOUNT_CREATION_ID = "registry-routing-account"
        const val BLOB_CREATION_ID = "registry-routing-blob"
        const val EMAIL_CREATION_ID = "registry-routing-email"
        const val SUBMISSION_CREATION_ID = "registry-routing-submission"
        const val REGISTRY_PAGE_SIZE = 100
        const val MAXIMUM_ACCOUNT_RECORDS = 10_000
        const val MAXIMUM_ACCOUNT_PAGES = 100
        const val MAXIMUM_CLEANUP_CANDIDATES = 8
        const val MAXIMUM_MARKER_RESULTS = 8
        const val DELIVERY_ATTEMPTS = 40
        const val DELIVERY_DELAY_MILLIS = 250L
    }
}
