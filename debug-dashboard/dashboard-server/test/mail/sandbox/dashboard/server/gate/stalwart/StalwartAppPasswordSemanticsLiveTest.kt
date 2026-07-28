package mail.sandbox.dashboard.server.gate.stalwart

import java.io.BufferedReader
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Instant
import java.util.Base64
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
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

class StalwartAppPasswordSemanticsLiveTest {
    @Test
    fun provesDirectAppPasswordAndPermissionSemantics() = runBlocking {
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
                    credential = GateCredential.bearer(fixture.managementApiKey),
                    transport = transport,
                ).use { manager ->
                    GateJmapClient(
                        baseUrl = live.baseUrl,
                        credential = GateCredential.basic(
                            username = GateBootstrap.FIRST_USER_ADDRESS,
                            secret = fixture.firstUserPassword,
                        ),
                        transport = transport,
                    ).use { owner ->
                        GateJmapClient(
                            baseUrl = live.baseUrl,
                            credential = GateCredential.basic(
                                username = GateBootstrap.SECOND_USER_ADDRESS,
                                secret = fixture.secondUserPassword,
                            ),
                            transport = transport,
                        ).use { recipient ->

                            val managementSession = manager.discoverSession()
                            val ownerSession = owner.discoverSession()
                            val recipientSession = recipient.discoverSession()
                            val ownerAccountId = requirePrimaryAccount(
                                session = ownerSession,
                                expectedUsername = GateBootstrap.FIRST_USER_ADDRESS,
                            )
                            val recipientAccountId = requirePrimaryAccount(
                                session = recipientSession,
                                expectedUsername = GateBootstrap.SECOND_USER_ADDRESS,
                            )
                            assertEquals(EXPECTED_API_URL, managementSession.apiUrl)
                            assertEquals(
                                fixture.managementAccountId,
                                managementSession.primaryAccountId,
                                "Management credential authenticated the wrong Account",
                            )
                            assertEquals(
                                GateBootstrap.MANAGEMENT_ADDRESS,
                                managementSession.username,
                                "Management credential returned the wrong username",
                            )
                            assertEquals(
                                3,
                                setOf(
                                    fixture.managementAccountId,
                                    ownerAccountId,
                                    recipientAccountId,
                                ).size,
                                "Gate credentials did not identify three distinct Accounts",
                            )

                            val enrollment = GateAppPasswordEnrollmentClient(
                                registry = owner,
                                ownerAccountId = ownerAccountId,
                                ownerAddress = GateBootstrap.FIRST_USER_ADDRESS,
                            )
                            val revoker = GateManagementAppPasswordRevoker(
                                registry = manager,
                                managementAccountId = fixture.managementAccountId,
                            )
                            val marker = UUID.randomUUID().toString()
                            val artifacts = LiveArtifacts(marker)
                            var firstSecret = CharArray(0)
                            var secondSecret = CharArray(0)
                            var firstAppToClose: GateJmapClient? = null
                            var secondAppToClose: GateJmapClient? = null
                            var primaryFailure: Throwable? = null

                            try {
                                cleanupReservedCredentials(
                                    enrollment = enrollment,
                                    owner = owner,
                                    ownerAccountId = ownerAccountId,
                                )

                                val first = enrollment.create(FIRST_DESCRIPTION)
                                val firstCredentialId = first.use { created ->
                                    firstSecret = created.copySecret()
                                    assertReadOnceSecret(firstSecret)
                                    created.id
                                }
                                val second = enrollment.create(SECOND_DESCRIPTION)
                                val secondCredentialId = second.use { created ->
                                    secondSecret = created.copySecret()
                                    assertReadOnceSecret(secondSecret)
                                    created.id
                                }

                                assertTwoMaskedCredentials(
                                    inventory = enrollment.inventory(),
                                    firstCredentialId = firstCredentialId,
                                    secondCredentialId = secondCredentialId,
                                )

                                val firstApp = appPasswordClient(
                                    live = live,
                                    transport = transport,
                                    secret = firstSecret,
                                ).also { firstAppToClose = it }
                                val secondApp = appPasswordClient(
                                    live = live,
                                    transport = transport,
                                    secret = secondSecret,
                                ).also { secondAppToClose = it }
                                assertOwnedSession(firstApp.discoverSession(), ownerAccountId)
                                assertOwnedSession(secondApp.discoverSession(), ownerAccountId)

                                assertSecretUpdateRejected(
                                    owner = owner,
                                    ownerAccountId = ownerAccountId,
                                    credentialId = firstCredentialId,
                                )
                                assertOwnedSession(
                                    appPasswordClient(live, transport, firstSecret).use {
                                        it.discoverSession()
                                    },
                                    ownerAccountId,
                                )
                                assertTwoMaskedCredentials(
                                    inventory = enrollment.inventory(),
                                    firstCredentialId = firstCredentialId,
                                    secondCredentialId = secondCredentialId,
                                )

                                val effectiveScopes =
                                    KtorGateHttpTransport(followRedirects = false).use { effectiveTransport ->
                                        listOf(firstSecret, secondSecret).map { secret ->
                                            GateEffectivePermissionClient(
                                                baseUrl = live.baseUrl,
                                                credential = GateCredential.basic(
                                                    username = GateBootstrap.FIRST_USER_ADDRESS,
                                                    secret = secret,
                                                ),
                                                transport = effectiveTransport,
                                            ).use { it.fetch() }
                                        }
                                    }
                                assertEquals(2, effectiveScopes.size)
                                effectiveScopes.forEach { effectiveScope ->
                                    assertEquals(
                                        DASHBOARD_MAIL_PERMISSIONS,
                                        effectiveScope.permissions,
                                        "Effective AppPassword scope differed from its Replace allowlist",
                                    )
                                    assertEquals(15, effectiveScope.permissions.size)
                                    assertFalse("emailSend" in effectiveScope.permissions)
                                    assertFalse(
                                        effectiveScope.permissions.any { permission ->
                                            permission == "impersonate" ||
                                                permission.startsWith("sys") ||
                                                "*" in permission
                                        },
                                        "Effective AppPassword scope contained an administrative grant",
                                    )
                                }

                                val normalSmtp = smtpAuthenticate(
                                    username = GateBootstrap.FIRST_USER_ADDRESS,
                                    secret = fixture.firstUserPassword,
                                )
                                assertSmtpMechanismBoundary(normalSmtp)
                                assertEquals(
                                    "235 2.7.0 Authentication succeeded.",
                                    normalSmtp.authResponse,
                                    "Normal-password SMTP control did not authenticate",
                                )
                                val appPasswordSmtp = smtpAuthenticate(
                                    username = GateBootstrap.FIRST_USER_ADDRESS,
                                    secret = firstSecret,
                                )
                                assertSmtpMechanismBoundary(appPasswordSmtp)
                                assertEquals(
                                    "550 5.7.1 Your account is not authorized to use this service.",
                                    appPasswordSmtp.authResponse,
                                    "SMTP did not distinguish valid AppPassword authentication " +
                                        "from its intentionally absent emailSend grant",
                                )

                                exerciseMailSequence(
                                    app = firstApp,
                                    recipient = recipient,
                                    ownerAccountId = ownerAccountId,
                                    recipientAccountId = recipientAccountId,
                                    marker = marker,
                                    artifacts = artifacts,
                                )

                                assertAuthenticationAndOwnershipNegatives(
                                    live = live,
                                    transport = transport,
                                    manager = manager,
                                    app = firstApp,
                                    ownerAccountId = ownerAccountId,
                                    recipientAccountId = recipientAccountId,
                                    firstSecret = firstSecret,
                                    secondCredentialId = secondCredentialId,
                                )

                                assertIs<GateTargetedRevocationResult.Revoked>(
                                    revoker.revoke(
                                        targetAccountId = ownerAccountId,
                                        targetCredentialId = firstCredentialId,
                                        expectedDescription = FIRST_DESCRIPTION,
                                    ),
                                )
                                assertAuthenticationRejected(
                                    appPasswordClient(
                                        live = live,
                                        transport = transport,
                                        secret = firstSecret,
                                    ),
                                    "Revoked AppPassword unexpectedly authenticated",
                                )
                                assertOwnedSession(
                                    appPasswordClient(live, transport, secondSecret).use {
                                        it.discoverSession()
                                    },
                                    ownerAccountId,
                                )
                                assertOwnedSession(owner.discoverSession(), ownerAccountId)

                                val afterRevocation = enrollment.inventory()
                                assertFalse(
                                    afterRevocation.any { it.id == firstCredentialId },
                                    "Targeted management revocation left the target credential present",
                                )
                                val preserved = afterRevocation.singleOrNull {
                                    it.id == secondCredentialId &&
                                        it.description.value == SECOND_DESCRIPTION.value
                                }
                                assertNotNull(
                                    preserved,
                                    "Targeted management revocation did not preserve the sibling credential",
                                )
                                assertEquals(DASHBOARD_MAIL_PERMISSIONS, preserved.permissions)
                            } catch (failure: Throwable) {
                                primaryFailure = failure
                                throw failure
                            } finally {
                                withContext(NonCancellable) {
                                    var cleanupFailure: Throwable? = null

                                    suspend fun attemptCleanup(block: suspend () -> Unit) {
                                        try {
                                            block()
                                        } catch (failure: Throwable) {
                                            cleanupFailure?.addSuppressed(failure)
                                                ?: run { cleanupFailure = failure }
                                        }
                                    }

                                    attemptCleanup {
                                        cleanupMailArtifacts(
                                            owner = owner,
                                            recipient = recipient,
                                            ownerAccountId = ownerAccountId,
                                            recipientAccountId = recipientAccountId,
                                            artifacts = artifacts,
                                        )
                                    }
                                    attemptCleanup {
                                        cleanupReservedCredentials(
                                            enrollment = enrollment,
                                            owner = owner,
                                            ownerAccountId = ownerAccountId,
                                        )
                                    }
                                    attemptCleanup {
                                        firstAppToClose?.close()
                                    }
                                    attemptCleanup {
                                        secondAppToClose?.close()
                                    }
                                    firstSecret.fill('\u0000')
                                    secondSecret.fill('\u0000')
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
        }
    }

    private suspend fun exerciseMailSequence(
        app: GateJmapClient,
        recipient: GateJmapClient,
        ownerAccountId: String,
        recipientAccountId: String,
        marker: String,
        artifacts: LiveArtifacts,
    ) {
        val mailboxGet = mailPayload(
            app.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("ids", JsonNull)
                    put(
                        "properties",
                        strings("id", "name", "parentId", "role"),
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Mailbox/get",
        )
        val inboxId = assertNotNull(
            requiredArray(mailboxGet, "list")
                .map(::requiredObject)
                .singleOrNull { mailbox ->
                    mailbox["role"]?.jsonPrimitive?.contentOrNull == "inbox"
                }
                ?.let { requiredString(it, "id") },
            "Mailbox/get did not return exactly one Inbox",
        )

        artifacts.mailboxCreateAttempted = true
        val createMailbox = mailPayload(
            app.call(
                methodName = "Mailbox/set",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                MAILBOX_CREATION_ID,
                                buildJsonObject {
                                    put("name", "Gate 0B AppPassword $marker")
                                    put("parentId", JsonNull)
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Mailbox/set",
        )
        requireNoSetFailures(createMailbox, "notCreated")
        val mailboxId = requiredString(
            requiredObject(
                requiredObject(createMailbox, "created")[MAILBOX_CREATION_ID],
            ),
            "id",
        )
        artifacts.mailboxIds += mailboxId

        val renameMailbox = mailPayload(
            app.call(
                methodName = "Mailbox/set",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "update",
                        buildJsonObject {
                            put(
                                mailboxId,
                                buildJsonObject {
                                    put("name", "Gate 0B AppPassword renamed $marker")
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Mailbox/set",
        )
        requireUpdated(renameMailbox, mailboxId)

        val subject = artifacts.subject
        val message = buildString {
            append("From: ${GateBootstrap.FIRST_USER_ADDRESS}\r\n")
            append("To: ${GateBootstrap.SECOND_USER_ADDRESS}\r\n")
            append("Subject: $subject\r\n")
            append("Date: Tue, 28 Jul 2026 12:00:00 -0300\r\n")
            append("Message-ID: <gate0b-$marker@local.test>\r\n")
            append("MIME-Version: 1.0\r\n")
            append("Content-Type: text/plain; charset=UTF-8\r\n")
            append("\r\n")
            append("Gate 0B body marker $marker\r\n")
        }
        val upload = mailPayload(
            app.call(
                methodName = "Blob/upload",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
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
            "Blob/upload",
        )
        requireNoSetFailures(upload, "notCreated")
        val createdBlob = requiredObject(
            requiredObject(upload, "created")[BLOB_CREATION_ID],
        )
        val blobId = requiredString(createdBlob, "id")
        assertEquals("message/rfc822", requiredString(createdBlob, "type"))
        assertEquals(
            message.encodeToByteArray().size.toLong(),
            requiredLong(createdBlob, "size"),
        )

        val blobGet = mailPayload(
            app.call(
                methodName = "Blob/get",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("ids", strings(blobId))
                    put("properties", strings("data:asText", "size"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Blob/get",
        )
        assertTrue(requiredArray(blobGet, "notFound").isEmpty())
        val fetchedBlob = requiredObject(requiredArray(blobGet, "list").single())
        assertEquals(message, requiredString(fetchedBlob, "data:asText"))
        assertEquals(
            message.encodeToByteArray().size.toLong(),
            requiredLong(fetchedBlob, "size"),
        )

        artifacts.emailImportAttempted = true
        val imported = mailPayload(
            app.call(
                methodName = "Email/import",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
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
                                            put(mailboxId, true)
                                        },
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
            "Email/import",
        )
        requireNoSetFailures(imported, "notCreated")
        val ownerEmailId = requiredString(
            requiredObject(
                requiredObject(imported, "created")[EMAIL_CREATION_ID],
            ),
            "id",
        )
        artifacts.ownerEmailIds += ownerEmailId

        val query = mailPayload(
            app.call(
                methodName = "Email/query",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "filter",
                        buildJsonObject {
                            put("inMailbox", mailboxId)
                        },
                    )
                    put("sort", buildJsonArray {})
                    put("limit", 10)
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Email/query",
        )
        assertTrue(
            ownerEmailId in requiredArray(query, "ids").map(::requiredString),
            "Email/query did not return the imported message",
        )

        val fetchedEmail = getEmail(
            client = app,
            accountId = ownerAccountId,
            emailId = ownerEmailId,
        )
        assertEquals(subject, requiredString(fetchedEmail, "subject"))
        assertTrue(requiredBooleanMap(fetchedEmail, "mailboxIds")[mailboxId] == true)
        assertTrue(requiredBooleanMap(fetchedEmail, "keywords")["\$draft"] == true)
        assertTrue(requiredBooleanMap(fetchedEmail, "keywords")["\$seen"] == true)
        val bodyValues = requiredObject(fetchedEmail, "bodyValues")
        assertTrue(
            bodyValues.values
                .map(::requiredObject)
                .map { requiredString(it, "value") }
                .any { marker in it },
            "Email/get did not return the imported text body",
        )

        val moved = mailPayload(
            app.call(
                methodName = "Email/set",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "update",
                        buildJsonObject {
                            put(
                                ownerEmailId,
                                buildJsonObject {
                                    put("mailboxIds/$inboxId", true)
                                    put("mailboxIds/$mailboxId", JsonNull)
                                    put("keywords/\$flagged", true)
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Email/set",
        )
        requireUpdated(moved, ownerEmailId)
        val movedEmail = getEmail(
            client = app,
            accountId = ownerAccountId,
            emailId = ownerEmailId,
        )
        val movedMailboxIds = requiredBooleanMap(movedEmail, "mailboxIds")
        assertTrue(movedMailboxIds[inboxId] == true)
        assertFalse(mailboxId in movedMailboxIds)
        assertTrue(requiredBooleanMap(movedEmail, "keywords")["\$flagged"] == true)

        destroyCreatedObject(
            client = app,
            methodName = "Mailbox/set",
            arguments = buildJsonObject {
                put("accountId", ownerAccountId)
                put("destroy", strings(mailboxId))
            },
            id = mailboxId,
            capabilities = MAIL_CAPABILITIES,
        )
        val identityGet = mailPayload(
            app.call(
                methodName = "Identity/get",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "email"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Identity/get",
        )
        val identityId = assertNotNull(
            requiredArray(identityGet, "list")
                .map(::requiredObject)
                .singleOrNull { identity ->
                    identity["email"]?.jsonPrimitive?.contentOrNull ==
                        GateBootstrap.FIRST_USER_ADDRESS
                }
                ?.let { requiredString(it, "id") },
            "Identity/get did not return the owner identity",
        )

        artifacts.submissionCreateAttempted = true
        val submitted = mailPayload(
            app.call(
                methodName = "EmailSubmission/set",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                SUBMISSION_CREATION_ID,
                                buildJsonObject {
                                    put("identityId", identityId)
                                    put("emailId", ownerEmailId)
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "EmailSubmission/set",
        )
        requireNoSetFailures(submitted, "notCreated")
        val createdSubmission = requiredObject(
            requiredObject(submitted, "created")[SUBMISSION_CREATION_ID],
        )
        val submissionId = requiredString(createdSubmission, "id")
        artifacts.submissionIds += submissionId
        assertTrue(requiredString(createdSubmission, "sendAt").isNotBlank())
        assertTrue(
            requiredString(createdSubmission, "undoStatus") in
                setOf("pending", "final"),
            "EmailSubmission/set returned an invalid undoStatus",
        )

        val submissionGet = mailPayload(
            app.call(
                methodName = "EmailSubmission/get",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("ids", strings(submissionId))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "EmailSubmission/get",
        )
        assertTrue(requiredArray(submissionGet, "notFound").isEmpty())
        assertEquals(
            submissionId,
            requiredString(
                requiredObject(requiredArray(submissionGet, "list").single()),
                "id",
            ),
        )

        val delivered = awaitRecipientDelivery(
            recipient = recipient,
            recipientAccountId = recipientAccountId,
            subject = subject,
        )
        artifacts.recipientDeliveryObserved = true
        artifacts.recipientEmailIds += delivered

        destroyCreatedObject(
            client = app,
            methodName = "Email/set",
            arguments = buildJsonObject {
                put("accountId", ownerAccountId)
                put("destroy", strings(ownerEmailId))
            },
            id = ownerEmailId,
            capabilities = MAIL_CAPABILITIES,
        )
    }

    private suspend fun assertAuthenticationAndOwnershipNegatives(
        live: StalwartLiveTestEnvironment,
        transport: GateHttpTransport,
        manager: GateJmapClient,
        app: GateJmapClient,
        ownerAccountId: String,
        recipientAccountId: String,
        firstSecret: CharArray,
        secondCredentialId: String,
    ) {
        val corrupted = corruptAppPassword(firstSecret)
        try {
            assertAuthenticationRejected(
                GateJmapClient(
                    baseUrl = live.baseUrl,
                    credential = GateCredential.basic(
                        username = GateBootstrap.FIRST_USER_ADDRESS,
                        secret = corrupted,
                    ),
                    transport = transport,
                ),
                "Modified AppPassword unexpectedly authenticated",
            )
        } finally {
            corrupted.fill('\u0000')
        }
        assertAuthenticationRejected(
            GateJmapClient(
                baseUrl = live.baseUrl,
                credential = GateCredential.basic(
                    username = GateBootstrap.SECOND_USER_ADDRESS,
                    secret = firstSecret,
                ),
                transport = transport,
            ),
            "Cross-Account username and AppPassword unexpectedly authenticated",
        )
        assertAuthenticationRejected(
            GateJmapClient(
                baseUrl = live.baseUrl,
                credential = GateCredential.basic(
                    username = GateBootstrap.MANAGEMENT_ADDRESS,
                    secret = firstSecret,
                ),
                transport = transport,
            ),
            "Management username and ordinary AppPassword unexpectedly authenticated",
        )
        assertAuthenticationRejected(
            GateJmapClient(
                baseUrl = live.baseUrl,
                credential = GateCredential.basic(
                    username = "${GateBootstrap.SECOND_USER_ADDRESS}%" +
                        GateBootstrap.FIRST_USER_ADDRESS,
                    secret = firstSecret,
                ),
                transport = transport,
            ),
            "AppPassword unexpectedly permitted target%credential impersonation",
        )

        assertMethodForbidden("Cross-Account Mailbox/get") {
            app.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", recipientAccountId)
                    put("ids", JsonNull)
                },
                capabilities = MAIL_CAPABILITIES,
            )
        }
        assertMethodForbidden("AppPassword Account/get") {
            app.registryGet(
                objectType = "Account",
                ids = listOf(ownerAccountId),
                accountId = ownerAccountId,
            )
        }
        for (objectType in listOf("Domain", "Task", "Log")) {
            assertMethodForbidden("AppPassword $objectType/query") {
                app.registryQuery(
                    objectType = objectType,
                    accountId = ownerAccountId,
                )
            }
        }
        assertMethodForbidden("AppPassword AccountPassword/set") {
            app.registryUpdate(
                objectType = "AccountPassword",
                objectId = "singleton",
                patch = buildJsonObject {
                    put("currentSecret", "forbidden-current-secret")
                    put("secret", "forbidden-replacement-secret")
                },
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("AppPassword AppPassword/query") {
            app.registryQuery(
                objectType = "AppPassword",
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("AppPassword AppPassword/create") {
            app.registryCreate(
                objectType = "AppPassword",
                creationId = "forbidden-app-password",
                value = secondaryCredentialProbe(),
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("AppPassword AppPassword/update") {
            app.registryUpdate(
                objectType = "AppPassword",
                objectId = secondCredentialId,
                patch = buildJsonObject {
                    put("description", "forbidden-update")
                },
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("AppPassword AppPassword/destroy") {
            app.registryDestroy(
                objectType = "AppPassword",
                objectId = secondCredentialId,
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("AppPassword ApiKey/query") {
            app.registryQuery(
                objectType = "ApiKey",
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("AppPassword ApiKey/create") {
            app.registryCreate(
                objectType = "ApiKey",
                creationId = "forbidden-api-key",
                value = secondaryCredentialProbe(),
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("AppPassword ApiKey/update") {
            app.registryUpdate(
                objectType = "ApiKey",
                objectId = "0",
                patch = buildJsonObject {
                    put("description", "forbidden-update")
                },
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("AppPassword ApiKey/destroy") {
            app.registryDestroy(
                objectType = "ApiKey",
                objectId = "0",
                accountId = ownerAccountId,
            )
        }

        assertMethodForbidden("Management Mailbox/get") {
            manager.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("ids", JsonNull)
                },
                capabilities = MAIL_CAPABILITIES,
            )
        }
        assertMethodForbidden("Management Email/query") {
            manager.call(
                methodName = "Email/query",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("filter", buildJsonObject {})
                    put("sort", buildJsonArray {})
                },
                capabilities = MAIL_CAPABILITIES,
            )
        }
        assertMethodForbidden("Management Mailbox/set") {
            manager.call(
                methodName = "Mailbox/set",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "update",
                        buildJsonObject {
                            put(
                                "forbidden-mailbox",
                                buildJsonObject {
                                    put("name", "forbidden-management-update")
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        }
        assertMethodForbidden("Management Email/set") {
            manager.call(
                methodName = "Email/set",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "update",
                        buildJsonObject {
                            put(
                                "forbidden-email",
                                buildJsonObject {
                                    put("keywords/\$flagged", true)
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        }
        assertMethodForbidden("Management Identity/get") {
            manager.call(
                methodName = "Identity/get",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("ids", JsonNull)
                },
                capabilities = MAIL_CAPABILITIES,
            )
        }
        assertMethodForbidden("Management Blob/upload") {
            manager.call(
                methodName = "Blob/upload",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                "forbidden",
                                buildJsonObject {
                                    put(
                                        "data",
                                        buildJsonArray {
                                            add(
                                                buildJsonObject {
                                                    put(
                                                        "data:asText",
                                                        "forbidden-management-probe",
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
            )
        }
        assertMethodForbidden("Management EmailSubmission/set") {
            manager.call(
                methodName = "EmailSubmission/set",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                "forbidden",
                                buildJsonObject {
                                    put("identityId", "0")
                                    put("emailId", "0")
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
        }
        assertMethodForbidden("Management AppPassword/query") {
            manager.registryQuery(
                objectType = "AppPassword",
                accountId = ownerAccountId,
            )
        }
        assertMethodForbidden("Management AppPassword/create") {
            manager.registryCreate(
                objectType = "AppPassword",
                creationId = "forbidden-management-app-password",
                value = secondaryCredentialProbe(),
                accountId = ownerAccountId,
            )
        }
    }

    private suspend fun cleanupReservedCredentials(
        enrollment: GateAppPasswordEnrollmentClient,
        owner: GateJmapClient,
        ownerAccountId: String,
    ) {
        val reservedDescriptions = setOf(
            FIRST_DESCRIPTION.value,
            SECOND_DESCRIPTION.value,
        )
        val credentials = enrollment.inventory()
            .filter { it.description.value in reservedDescriptions }
        var cleanupFailure: Throwable? = null
        credentials.forEach { credential ->
            try {
                destroyObject(
                    client = owner,
                    methodName = "x:AppPassword/set",
                    arguments = buildJsonObject {
                        put("accountId", ownerAccountId)
                        put("destroy", strings(credential.id))
                    },
                    id = credential.id,
                    capabilities = REGISTRY_CAPABILITIES,
                )
            } catch (failure: Throwable) {
                cleanupFailure?.addSuppressed(failure)
                    ?: run { cleanupFailure = failure }
            }
        }
        try {
            assertTrue(
                enrollment.inventory().none {
                    it.description.value in reservedDescriptions
                },
                "Reserved live-test AppPasswords remained after cleanup",
            )
        } catch (failure: Throwable) {
            cleanupFailure?.addSuppressed(failure)
                ?: run { cleanupFailure = failure }
        }
        cleanupFailure?.let { throw it }
    }

    private suspend fun cleanupMailArtifacts(
        owner: GateJmapClient,
        recipient: GateJmapClient,
        ownerAccountId: String,
        recipientAccountId: String,
        artifacts: LiveArtifacts,
    ) {
        var cleanupFailure: Throwable? = null

        suspend fun attemptCleanup(block: suspend () -> Unit) {
            try {
                block()
            } catch (failure: Throwable) {
                cleanupFailure?.addSuppressed(failure)
                    ?: run { cleanupFailure = failure }
            }
        }

        if (artifacts.mailboxCreateAttempted) {
            attemptCleanup {
                artifacts.mailboxIds += exactMarkerMailboxIds(
                    owner = owner,
                    ownerAccountId = ownerAccountId,
                    names = artifacts.mailboxNames,
                )
            }
        }
        if (artifacts.emailImportAttempted) {
            attemptCleanup {
                artifacts.ownerEmailIds += exactSubjectEmailIds(
                    client = owner,
                    accountId = ownerAccountId,
                    subject = artifacts.subject,
                )
            }
        }
        if (artifacts.submissionCreateAttempted) {
            attemptCleanup {
                artifacts.submissionIds += relatedSubmissionIds(
                    owner = owner,
                    ownerAccountId = ownerAccountId,
                    ownerEmailIds = artifacts.ownerEmailIds,
                )
            }
        }

        artifacts.submissionIds.toList().forEach { submissionId ->
            attemptCleanup {
                destroyObject(
                    client = owner,
                    methodName = "EmailSubmission/set",
                    arguments = buildJsonObject {
                        put("accountId", ownerAccountId)
                        put("destroy", strings(submissionId))
                    },
                    id = submissionId,
                    capabilities = MAIL_CAPABILITIES,
                )
            }
        }
        artifacts.ownerEmailIds.toList().forEach { emailId ->
            attemptCleanup {
                destroyObject(
                    client = owner,
                    methodName = "Email/set",
                    arguments = buildJsonObject {
                        put("accountId", ownerAccountId)
                        put("destroy", strings(emailId))
                    },
                    id = emailId,
                    capabilities = MAIL_CAPABILITIES,
                )
            }
        }

        suspend fun destroyRecipientEmail(emailId: String) {
            attemptCleanup {
                destroyObject(
                    client = recipient,
                    methodName = "Email/set",
                    arguments = buildJsonObject {
                        put("accountId", recipientAccountId)
                        put("destroy", strings(emailId))
                    },
                    id = emailId,
                    capabilities = MAIL_CAPABILITIES,
                )
            }
        }

        artifacts.recipientEmailIds.toList().forEach { emailId ->
            destroyRecipientEmail(emailId)
        }
        if (artifacts.submissionCreateAttempted) {
            val attempts = if (artifacts.recipientDeliveryObserved) {
                1
            } else {
                DELIVERY_ATTEMPTS
            }
            repeat(attempts) { attempt ->
                var discovered = emptySet<String>()
                attemptCleanup {
                    discovered = exactSubjectEmailIds(
                        client = recipient,
                        accountId = recipientAccountId,
                        subject = artifacts.subject,
                    )
                    artifacts.recipientEmailIds += discovered
                }
                discovered.forEach { emailId ->
                    destroyRecipientEmail(emailId)
                }
                if (attempt + 1 < attempts) {
                    delay(DELIVERY_DELAY_MILLIS)
                }
            }
        }

        artifacts.mailboxIds.toList().forEach { mailboxId ->
            attemptCleanup {
                destroyObject(
                    client = owner,
                    methodName = "Mailbox/set",
                    arguments = buildJsonObject {
                        put("accountId", ownerAccountId)
                        put("destroy", strings(mailboxId))
                    },
                    id = mailboxId,
                    capabilities = MAIL_CAPABILITIES,
                )
            }
        }

        if (artifacts.mailboxCreateAttempted) {
            attemptCleanup {
                assertTrue(
                    exactMarkerMailboxIds(
                        owner = owner,
                        ownerAccountId = ownerAccountId,
                        names = artifacts.mailboxNames,
                    ).isEmpty(),
                    "Marker mailbox remained after cleanup reconciliation",
                )
            }
        }
        if (artifacts.emailImportAttempted) {
            attemptCleanup {
                assertTrue(
                    exactSubjectEmailIds(
                        client = owner,
                        accountId = ownerAccountId,
                        subject = artifacts.subject,
                    ).isEmpty(),
                    "Owner marker email remained after cleanup reconciliation",
                )
            }
        }
        if (artifacts.submissionCreateAttempted) {
            attemptCleanup {
                assertTrue(
                    relatedSubmissionIds(
                        owner = owner,
                        ownerAccountId = ownerAccountId,
                        ownerEmailIds = artifacts.ownerEmailIds,
                    ).isEmpty(),
                    "Marker EmailSubmission remained after cleanup reconciliation",
                )
            }
            attemptCleanup {
                assertTrue(
                    exactSubjectEmailIds(
                        client = recipient,
                        accountId = recipientAccountId,
                        subject = artifacts.subject,
                    ).isEmpty(),
                    "Recipient marker email remained after cleanup reconciliation",
                )
            }
        }
        cleanupFailure?.let { throw it }
    }

    private suspend fun exactMarkerMailboxIds(
        owner: GateJmapClient,
        ownerAccountId: String,
        names: Set<String>,
    ): Set<String> {
        val payload = mailPayload(
            owner.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "name"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Mailbox/get",
        )
        assertTrue(requiredArray(payload, "notFound").isEmpty())
        return requiredArray(payload, "list")
            .map(::requiredObject)
            .filter { mailbox -> requiredString(mailbox, "name") in names }
            .map { mailbox -> requiredString(mailbox, "id") }
            .toSet()
    }

    private suspend fun exactSubjectEmailIds(
        client: GateJmapClient,
        accountId: String,
        subject: String,
    ): Set<String> {
        val query = mailPayload(
            client.call(
                methodName = "Email/query",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "filter",
                        buildJsonObject {
                            put("subject", subject)
                        },
                    )
                    put("sort", buildJsonArray {})
                    put("position", 0)
                    put("limit", CLEANUP_QUERY_LIMIT)
                    put("calculateTotal", true)
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Email/query",
        )
        val ids = requiredArray(query, "ids").map(::requiredString)
        assertEquals(ids.size, ids.toSet().size, "Email/query returned duplicate IDs")
        assertEquals(0L, requiredLong(query, "position"))
        assertEquals(
            ids.size.toLong(),
            requiredLong(query, "total"),
            "Email/query cleanup result was incomplete",
        )
        if (ids.isEmpty()) return emptySet()

        val get = mailPayload(
            client.call(
                methodName = "Email/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonArray(ids.map(::JsonPrimitive)))
                    put("properties", strings("id", "subject"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Email/get",
        )
        val missing = requiredArray(get, "notFound").map(::requiredString).toSet()
        val emails = requiredArray(get, "list").map(::requiredObject)
        val returnedIds = emails.map { email -> requiredString(email, "id") }
        assertEquals(
            ids.toSet(),
            returnedIds.toSet() + missing,
            "Email/get did not account for the exact cleanup query IDs",
        )
        return emails
            .filter { email -> requiredString(email, "subject") == subject }
            .map { email -> requiredString(email, "id") }
            .toSet()
    }

    private suspend fun relatedSubmissionIds(
        owner: GateJmapClient,
        ownerAccountId: String,
        ownerEmailIds: Set<String>,
    ): Set<String> {
        if (ownerEmailIds.isEmpty()) return emptySet()
        val payload = mailPayload(
            owner.call(
                methodName = "EmailSubmission/get",
                arguments = buildJsonObject {
                    put("accountId", ownerAccountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "emailId"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "EmailSubmission/get",
        )
        assertTrue(requiredArray(payload, "notFound").isEmpty())
        return requiredArray(payload, "list")
            .map(::requiredObject)
            .filter { submission ->
                requiredString(submission, "emailId") in ownerEmailIds
            }
            .map { submission -> requiredString(submission, "id") }
            .toSet()
    }

    private suspend fun destroyObject(
        client: GateJmapClient,
        methodName: String,
        arguments: JsonObject,
        id: String,
        capabilities: List<GateJmapCapability>,
    ) {
        val payload = mailPayload(
            client.call(
                methodName = methodName,
                arguments = arguments,
                capabilities = capabilities,
            ),
            methodName,
        )
        val destroyed = (payload["destroyed"] as? JsonArray)
            .orEmpty()
            .map(::requiredString)
        if (id in destroyed) return
        val notDestroyed = (payload["notDestroyed"] as? JsonObject)
            ?.get(id) as? JsonObject
        assertEquals(
            "notFound",
            notDestroyed?.get("type")?.jsonPrimitive?.contentOrNull,
            "$methodName cleanup neither destroyed nor proved the object absent",
        )
    }

    private suspend fun destroyCreatedObject(
        client: GateJmapClient,
        methodName: String,
        arguments: JsonObject,
        id: String,
        capabilities: List<GateJmapCapability>,
    ) {
        val payload = mailPayload(
            client.call(
                methodName = methodName,
                arguments = arguments,
                capabilities = capabilities,
            ),
            methodName,
        )
        assertTrue(
            (payload["notDestroyed"] as? JsonObject).orEmpty().isEmpty(),
            "$methodName rejected deletion of the exact live-test object",
        )
        assertEquals(
            listOf(id),
            requiredArray(payload, "destroyed").map(::requiredString),
            "$methodName did not confirm deletion of the exact live-test object",
        )
    }

    private suspend fun awaitRecipientDelivery(
        recipient: GateJmapClient,
        recipientAccountId: String,
        subject: String,
    ): Set<String> {
        repeat(DELIVERY_ATTEMPTS) { attempt ->
            val payload = mailPayload(
                recipient.call(
                    methodName = "Email/query",
                    arguments = buildJsonObject {
                        put("accountId", recipientAccountId)
                        put(
                            "filter",
                            buildJsonObject {
                                put("subject", subject)
                            },
                        )
                        put("sort", buildJsonArray {})
                        put("limit", 10)
                    },
                    capabilities = MAIL_CAPABILITIES,
                ),
                "Email/query",
            )
            val ids = requiredArray(payload, "ids")
                .map(::requiredString)
                .toSet()
            if (ids.isNotEmpty()) {
                assertEquals(
                    1,
                    ids.size,
                    "JMAP submission delivered an unexpected duplicate probe",
                )
                val email = getEmail(
                    client = recipient,
                    accountId = recipientAccountId,
                    emailId = ids.single(),
                )
                assertEquals(
                    subject,
                    requiredString(email, "subject"),
                    "Recipient Email/get returned the wrong delivered probe",
                )
                return ids
            }
            if (attempt + 1 < DELIVERY_ATTEMPTS) {
                delay(DELIVERY_DELAY_MILLIS)
            }
        }
        throw AssertionError(
            "JMAP submission did not deliver the probe to the registered recipient",
        )
    }

    private suspend fun getEmail(
        client: GateJmapClient,
        accountId: String,
        emailId: String,
    ): JsonObject {
        val payload = mailPayload(
            client.call(
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
            "Email/get",
        )
        assertTrue(requiredArray(payload, "notFound").isEmpty())
        val list = requiredArray(payload, "list")
        assertEquals(1, list.size, "Email/get returned the wrong object count")
        val email = requiredObject(list.single())
        assertEquals(emailId, requiredString(email, "id"))
        return email
    }

    private suspend fun assertSecretUpdateRejected(
        owner: GateJmapClient,
        ownerAccountId: String,
        credentialId: String,
    ) {
        val payload = mailPayload(
            owner.registryUpdate(
                objectType = "AppPassword",
                objectId = credentialId,
                patch = buildJsonObject {
                    put("secret", "replacement-must-remain-server-set")
                },
                accountId = ownerAccountId,
            ),
            "x:AppPassword/set",
        )
        assertFalse(
            credentialId in (payload["updated"] as? JsonObject).orEmpty(),
            "Server-set AppPassword secret unexpectedly reported an update",
        )
        val notUpdated = requiredObject(
            requiredObject(payload, "notUpdated")[credentialId],
        )
        assertEquals("invalidPatch", requiredString(notUpdated, "type"))
    }

    private fun assertTwoMaskedCredentials(
        inventory: List<GateStoredAppPassword>,
        firstCredentialId: String,
        secondCredentialId: String,
    ) {
        val relevant = inventory.filter {
            it.description.value in setOf(
                FIRST_DESCRIPTION.value,
                SECOND_DESCRIPTION.value,
            )
        }
        assertEquals(
            setOf(firstCredentialId, secondCredentialId),
            relevant.map { it.id }.toSet(),
            "The two bounded-rotation credentials were not simultaneously present",
        )
        assertEquals(
            setOf(FIRST_DESCRIPTION.value, SECOND_DESCRIPTION.value),
            relevant.map { it.description.value }.toSet(),
        )
        assertTrue(
            relevant.all { it.permissions == DASHBOARD_MAIL_PERMISSIONS },
            "A stored credential differed from the exact Replace allowlist",
        )
    }

    private fun assertReadOnceSecret(secret: CharArray) {
        assertTrue(secret.size > 8, "Created AppPassword secret was unexpectedly short")
        assertTrue(
            secret.size >= 4 &&
                secret[0] == 'a' &&
                secret[1] == 'p' &&
                secret[2] == 'p' &&
                secret[3] == '_',
            "Created AppPassword did not use the pinned server-generated format",
        )
        assertFalse(
            secret.contentEquals(charArrayOf('*', '*', '*', '*')),
            "AppPassword creation returned the non-recoverable mask",
        )
    }

    private fun appPasswordClient(
        live: StalwartLiveTestEnvironment,
        transport: GateHttpTransport,
        secret: CharArray,
    ): GateJmapClient =
        GateJmapClient(
            baseUrl = live.baseUrl,
            credential = GateCredential.basic(
                username = GateBootstrap.FIRST_USER_ADDRESS,
                secret = secret,
            ),
            transport = transport,
        )

    private fun assertOwnedSession(
        session: GateJmapSession,
        ownerAccountId: String,
    ) {
        assertEquals(EXPECTED_API_URL, session.apiUrl)
        assertEquals(ownerAccountId, session.primaryAccountId)
        assertEquals(GateBootstrap.FIRST_USER_ADDRESS, session.username)
    }

    private fun requirePrimaryAccount(
        session: GateJmapSession,
        expectedUsername: String,
    ): String {
        assertEquals(EXPECTED_API_URL, session.apiUrl)
        assertEquals(expectedUsername, session.username)
        val accountId = assertNotNull(
            session.primaryAccountId,
            "Authenticated Session omitted its primary Account",
        )
        assertTrue(accountId.isNotBlank())
        return accountId
    }

    private suspend fun assertAuthenticationRejected(
        client: GateJmapClient,
        message: String,
    ) {
        val failure = client.use {
            assertFailsWith<GateJmapException> {
                it.discoverSession()
            }
        }
        val status = (failure.kind as? GateJmapFailure.HttpStatus)?.status
        assertTrue(
            status == 401 || status == 403,
            "$message for an unrelated reason",
        )
    }

    private suspend fun assertMethodForbidden(
        label: String,
        operation: suspend () -> JsonObject,
    ) {
        val failure = assertFailsWith<GateJmapException> {
            operation()
        }
        assertEquals(
            "forbidden",
            (failure.kind as? GateJmapFailure.MethodError)?.type,
            "$label failed for an unrelated reason",
        )
    }

    private fun corruptAppPassword(secret: CharArray): CharArray {
        require(secret.size > 12) { "AppPassword is too short for a bounded corruption probe" }
        return secret.copyOf().also { corrupted ->
            val index = corrupted.size / 2
            corrupted[index] = if (corrupted[index] == 'a') 'b' else 'a'
        }
    }

    private fun secondaryCredentialProbe(): JsonObject =
        buildJsonObject {
            put("description", "mail-sandbox/debug-dashboard/forbidden-probe")
            put(
                "permissions",
                buildJsonObject {
                    put("@type", "Replace")
                    put(
                        "permissions",
                        buildJsonObject {
                            put("authenticate", true)
                        },
                    )
                },
            )
            put("allowedIps", buildJsonObject {})
        }

    private suspend fun smtpAuthenticate(
        username: String,
        secret: CharArray,
    ): SmtpProbe =
        withContext(Dispatchers.IO) {
            Socket().use { socket ->
                socket.connect(
                    InetSocketAddress(SMTP_HOST, SMTP_PORT),
                    SMTP_CONNECT_TIMEOUT_MILLIS,
                )
                socket.soTimeout = SMTP_READ_TIMEOUT_MILLIS
                val reader = socket.getInputStream()
                    .bufferedReader(StandardCharsets.US_ASCII)
                val output = socket.getOutputStream()
                val greeting = readSmtpResponse(reader)
                assertEquals(220, greeting.code, "SMTP greeting was invalid")

                writeAscii(output, "EHLO gate0b.local\r\n")
                val ehlo = readSmtpResponse(reader)
                assertEquals(250, ehlo.code, "SMTP EHLO was rejected")

                writeAuthPlain(
                    output = output,
                    username = username,
                    secret = secret,
                )
                val auth = readSmtpResponse(reader)

                writeAscii(output, "QUIT\r\n")
                val quit = readSmtpResponse(reader)
                assertEquals(221, quit.code, "SMTP QUIT was rejected")
                SmtpProbe(
                    ehloLines = ehlo.lines,
                    authResponse = auth.lines.singleOrNull()
                        ?: throw AssertionError(
                            "SMTP AUTH returned an invalid response shape",
                        ),
                )
            }
        }

    private fun assertSmtpMechanismBoundary(probe: SmtpProbe) {
        val capabilities = probe.ehloLines.map { line ->
            require(line.length >= 4) { "SMTP EHLO returned a malformed line" }
            line.substring(4)
        }
        assertTrue(
            capabilities.any { capability ->
                capability.split(' ').firstOrNull() == "AUTH" &&
                    "PLAIN" in capability.split(' ')
            },
            "Loopback SMTP did not advertise AUTH PLAIN",
        )
        assertFalse(
            capabilities.any { it.split(' ').firstOrNull() == "STARTTLS" },
            "Plaintext proof listener unexpectedly advertised STARTTLS",
        )
    }

    private fun writeAuthPlain(
        output: OutputStream,
        username: String,
        secret: CharArray,
    ) {
        require(username.all { it.code in 1..127 }) {
            "SMTP proof username must be ASCII"
        }
        require(secret.isNotEmpty() && secret.all { it.code in 1..127 }) {
            "SMTP proof secret must be non-empty ASCII"
        }
        val usernameBytes = username.toByteArray(StandardCharsets.US_ASCII)
        val secretBytes = ByteArray(secret.size) { index ->
            secret[index].code.toByte()
        }
        val challenge = ByteArray(usernameBytes.size + secretBytes.size + 2)
        val encoded = try {
            challenge[0] = 0
            usernameBytes.copyInto(challenge, destinationOffset = 1)
            challenge[usernameBytes.size + 1] = 0
            secretBytes.copyInto(
                challenge,
                destinationOffset = usernameBytes.size + 2,
            )
            Base64.getEncoder().encode(challenge)
        } finally {
            usernameBytes.fill(0)
            secretBytes.fill(0)
            challenge.fill(0)
        }
        try {
            output.write("AUTH PLAIN ".toByteArray(StandardCharsets.US_ASCII))
            output.write(encoded)
            output.write("\r\n".toByteArray(StandardCharsets.US_ASCII))
            output.flush()
        } finally {
            encoded.fill(0)
        }
    }

    private fun writeAscii(output: OutputStream, value: String) {
        output.write(value.toByteArray(StandardCharsets.US_ASCII))
        output.flush()
    }

    private fun readSmtpResponse(reader: BufferedReader): SmtpResponse {
        val lines = mutableListOf<String>()
        var expectedCode: Int? = null
        repeat(MAX_SMTP_RESPONSE_LINES) {
            val line = reader.readLine()
                ?: throw AssertionError("SMTP closed before a complete response")
            require(line.length in 4..MAX_SMTP_LINE_CHARS) {
                "SMTP returned a malformed response line"
            }
            val code = line.substring(0, 3).toIntOrNull()
                ?: throw AssertionError("SMTP returned an invalid response code")
            if (expectedCode == null) {
                expectedCode = code
            } else {
                assertEquals(
                    expectedCode,
                    code,
                    "SMTP multiline response changed its status code",
                )
            }
            lines += line
            when (line[3]) {
                ' ' -> return SmtpResponse(
                    code = assertNotNull(expectedCode),
                    lines = lines,
                )
                '-' -> Unit
                else -> throw AssertionError(
                    "SMTP returned an invalid multiline separator",
                )
            }
        }
        throw AssertionError("SMTP response exceeded its line bound")
    }

    private fun mailPayload(
        response: JsonObject,
        expectedMethod: String,
    ): JsonObject {
        val responses = response["methodResponses"] as? JsonArray
        assertNotNull(responses, "$expectedMethod omitted methodResponses")
        assertEquals(
            1,
            responses.size,
            "$expectedMethod returned an unexpected implicit method",
        )
        val method = responses.single() as? JsonArray
        assertNotNull(method, "$expectedMethod returned a malformed tuple")
        assertEquals(3, method.size, "$expectedMethod returned an invalid tuple")
        assertEquals(expectedMethod, method[0].jsonPrimitive.content)
        assertTrue(method[2].jsonPrimitive.content.isNotBlank())
        return method[1] as? JsonObject
            ?: throw AssertionError("$expectedMethod returned a malformed payload")
    }

    private fun requireNoSetFailures(payload: JsonObject, property: String) {
        assertTrue(
            (payload[property] as? JsonObject).orEmpty().isEmpty(),
            "JMAP set response contained $property",
        )
    }

    private fun requireUpdated(payload: JsonObject, id: String) {
        requireNoSetFailures(payload, "notUpdated")
        assertTrue(
            id in (payload["updated"] as? JsonObject).orEmpty(),
            "JMAP set response did not confirm the exact updated object",
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
            values.forEach { add(JsonPrimitive(it)) }
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

    private class LiveArtifacts(marker: String) {
        val subject = "Gate 0B AppPassword semantics $marker"
        val mailboxNames = setOf(
            "Gate 0B AppPassword $marker",
            "Gate 0B AppPassword renamed $marker",
        )
        var mailboxCreateAttempted = false
        var emailImportAttempted = false
        var submissionCreateAttempted = false
        var recipientDeliveryObserved = false
        val mailboxIds = linkedSetOf<String>()
        val ownerEmailIds = linkedSetOf<String>()
        val submissionIds = linkedSetOf<String>()
        val recipientEmailIds = linkedSetOf<String>()
    }

    private data class SmtpProbe(
        val ehloLines: List<String>,
        val authResponse: String,
    )

    private data class SmtpResponse(
        val code: Int,
        val lines: List<String>,
    )

    private companion object {
        val EXPECTED_API_URL: URI = URI("http://127.0.0.1:18443/jmap/")
        val STORE_ID: UUID =
            UUID.fromString("53602687-653f-41d4-a9ad-e2ebff7e093e")
        val FIRST_DESCRIPTION =
            GateAppPasswordDescription.reserved(STORE_ID, 1u)
        val SECOND_DESCRIPTION =
            GateAppPasswordDescription.reserved(STORE_ID, 2u)
        val MAIL_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.MAIL,
            GateJmapCapability.SUBMISSION,
            GateJmapCapability.BLOB,
        )
        val REGISTRY_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.STALWART,
        )
        const val MAILBOX_CREATION_ID = "gate-mailbox"
        const val BLOB_CREATION_ID = "gate-blob"
        const val EMAIL_CREATION_ID = "gate-email"
        const val SUBMISSION_CREATION_ID = "gate-submission"
        const val SMTP_HOST = "127.0.0.1"
        const val SMTP_PORT = 18_587
        const val SMTP_CONNECT_TIMEOUT_MILLIS = 3_000
        const val SMTP_READ_TIMEOUT_MILLIS = 5_000
        const val MAX_SMTP_RESPONSE_LINES = 64
        const val MAX_SMTP_LINE_CHARS = 2_048
        const val DELIVERY_ATTEMPTS = 40
        const val DELIVERY_DELAY_MILLIS = 250L
        const val CLEANUP_QUERY_LIMIT = 100
    }
}
