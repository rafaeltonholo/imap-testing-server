package mail.sandbox.dashboard.server.gate.stalwart

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import java.util.Base64
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStoreLoadResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStorePaths
import mail.sandbox.dashboard.server.provider.stalwart.credential.FileStalwartCredentialStore
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessState
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccount
import kotlin.io.path.createDirectories
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class StalwartRoutingProofCliTest {
    @Test
    fun argumentsPinTheDashboardRootInvocationAndMigrationProfile() {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"

        val arguments = StalwartRoutingProofArguments.parse(
            arrayOf(
                "--dashboard-project-root",
                dashboardRoot.toString(),
                "--invocation-id",
                invocationId,
            ),
        )

        assertEquals(
            dashboardRoot.toRealPath(LinkOption.NOFOLLOW_LINKS),
            arguments.dashboardProjectRoot,
        )
        assertEquals(invocationId, arguments.invocationId)
        assertEquals(
            StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
            arguments.endpointProfile,
        )
        assertEquals(
            dashboardRoot.resolve(
                ".runtime/stalwart/bootstrap-routing-input.json",
            ),
            arguments.paths.input,
        )
        assertEquals(
            dashboardRoot.resolve(
                ".runtime/secrets/stalwart-routing-sender-password",
            ),
            arguments.paths.senderPassword,
        )
        assertEquals(
            dashboardRoot.resolve(
                ".runtime/secrets/stalwart-routing-recipient-password",
            ),
            arguments.paths.recipientPassword,
        )
    }

    @Test
    fun argumentsRejectExtraReorderedRelativeAndMalformedValues() {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"
        val valid = arrayOf(
            "--dashboard-project-root",
            dashboardRoot.toString(),
            "--invocation-id",
            invocationId,
        )

        listOf(
            emptyArray(),
            valid + "--endpoint",
            arrayOf(
                "--invocation-id",
                invocationId,
                "--dashboard-project-root",
                dashboardRoot.toString(),
            ),
            arrayOf(
                "--dashboard-project-root",
                Path.of("debug-dashboard").toString(),
                "--invocation-id",
                invocationId,
            ),
            arrayOf(
                "--dashboard-project-root",
                dashboardRoot.toString(),
                "--invocation-id",
                invocationId.uppercase(),
            ),
            arrayOf(
                "--dashboard-project-root",
                dashboardRoot.toString(),
                "--invocation-id",
                "../$invocationId",
            ),
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                StalwartRoutingProofArguments.parse(invalid)
            }
        }
    }

    @Test
    fun strictInputUsesOnlyFixedNonSecretMetadataAndActorFields() {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"
        val arguments = arguments(dashboardRoot, invocationId)
        writeRoutingInput(arguments.paths.input, validInput(invocationId))

        val input = StalwartRoutingProofInputFiles.read(arguments)

        assertEquals("managementaccount", input.managementAccountId)
        assertEquals("managementcredential", input.managementCredentialId)
        assertEquals("senderaccount", input.sender.accountId)
        assertEquals(
            "dashboard-routing-sender-$invocationId@local.test",
            input.sender.address,
        )
        assertEquals("recipientaccount", input.recipient.accountId)
        assertEquals(
            "dashboard-routing-recipient-$invocationId@local.test",
            input.recipient.address,
        )
        assertEquals("bootstrap-proof.json", input.bootstrapProof["name"]?.toString()?.trim('"'))
        assertFalse(input.toString().contains("password", ignoreCase = true))
    }

    @Test
    fun strictInputRejectsDuplicateKeysUnexpectedFieldsAndSecretPathFields() {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"
        val arguments = arguments(dashboardRoot, invocationId)
        val valid = validInput(invocationId)

        val unexpected = JsonObject(
            valid + ("sender_password_path" to JsonPrimitive("/tmp/secret")),
        )
        writeRoutingInput(arguments.paths.input, unexpected)
        assertFailsWith<IllegalArgumentException> {
            StalwartRoutingProofInputFiles.read(arguments)
        }

        Files.writeString(
            arguments.paths.input,
            canonicalJson(valid).dropLast(1) +
                ""","schema":"mail-sandbox.stalwart-v016-routing-input.v1"}""" +
                "\n",
            StandardCharsets.UTF_8,
        )
        assertFailsWith<IllegalArgumentException> {
            StalwartRoutingProofInputFiles.read(arguments)
        }
    }

    @Test
    fun routingPasswordAcceptsOnlyVisibleAsciiAndWipesOnClose() {
        val dashboardRoot = temporaryDashboardRoot()
        val path = dashboardRoot.resolve(
            ".runtime/secrets/stalwart-routing-sender-password",
        )
        writeSecret(path, SECRET_CANARY)
        val password = StalwartRoutingPassword.read(dashboardRoot, path)
        val clear = password.copyValue()
        try {
            assertContentEquals(SECRET_CANARY.toCharArray(), clear)
        } finally {
            clear.fill('\u0000')
            password.close()
        }
        assertFailsWith<IllegalStateException> {
            password.copyValue()
        }

        listOf("contains space", "caf\u00e9").forEach { malformed ->
            writeSecret(path, malformed)
            assertFailsWith<IllegalArgumentException> {
                StalwartRoutingPassword.read(dashboardRoot, path)
            }
        }
    }

    @Test
    fun cliEmitsOneCanonicalSecretFreeVerifierEvidenceLine() = runBlocking {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"
        val evidence = validEvidence(invocationId)
        val workflow = RecordingWorkflow(evidence)
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()
        val cli = StalwartRoutingProofCli(
            workflowFactory = StalwartRoutingProofWorkflowFactory {
                workflow
            },
            clock = {
                Instant.parse("2026-07-28T12:34:56.987654321Z")
            },
        )

        val exitCode = cli.execute(
            args = argumentsArray(dashboardRoot, invocationId),
            stdout = PrintStream(stdout, true, StandardCharsets.UTF_8),
            stderr = PrintStream(stderr, true, StandardCharsets.UTF_8),
        )

        assertEquals(0, exitCode)
        assertEquals("", stderr.toString(StandardCharsets.UTF_8))
        val output = stdout.toString(StandardCharsets.UTF_8)
        assertEquals(1, output.count { it == '\n' })
        assertTrue(output.endsWith("\n"))
        assertFalse(output.contains(SECRET_CANARY))
        val payload = Json.parseToJsonElement(output.trimEnd()).jsonObject
        assertEquals(
            setOf(
                "actors",
                "bootstrap_proof",
                "invocation_id",
                "management_account_id",
                "management_credential_id",
                "message_id",
                "preserved_objects_sha256",
                "probes",
                "proven_at",
                "recipient_access_removed",
                "schema",
                "server_version",
            ),
            payload.keys,
        )
        assertEquals(
            "mail-sandbox.stalwart-v016-routing-verifier.v1",
            payload.getValue("schema").toString().trim('"'),
        )
        assertEquals(
            "2026-07-28T12:34:56Z",
            payload.getValue("proven_at").toString().trim('"'),
        )
        assertEquals(
            setOf(
                "external",
                "protected_exact",
                "protected_subaddress",
                "registered_local",
                "unregistered_local",
            ),
            payload.getValue("probes").jsonObject.keys,
        )
        assertEquals(
            StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
            workflow.request?.endpointProfile,
        )
        assertEquals(
            dashboardRoot.toRealPath(LinkOption.NOFOLLOW_LINKS),
            workflow.request?.dashboardProjectRoot,
        )
        assertTrue(workflow.closed)
    }

    @Test
    fun cliRejectsNonCanonicalProbeSemanticsBeforeWritingStdout() = runBlocking {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"
        val valid = validEvidence(invocationId)
        val external = JsonObject(
            valid.probes.getValue("external") + ("smtp_code" to JsonPrimitive(451)),
        )
        val invalid = valid.copy(
            probes = valid.probes + ("external" to external),
        )
        val workflow = RecordingWorkflow(invalid)
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()

        val exitCode = StalwartRoutingProofCli(
            workflowFactory = StalwartRoutingProofWorkflowFactory { workflow },
            clock = { Instant.parse("2026-07-28T12:34:56Z") },
        ).execute(
            args = argumentsArray(dashboardRoot, invocationId),
            stdout = PrintStream(stdout, true, StandardCharsets.UTF_8),
            stderr = PrintStream(stderr, true, StandardCharsets.UTF_8),
        )

        assertEquals(1, exitCode)
        assertEquals("", stdout.toString(StandardCharsets.UTF_8))
        assertEquals(
            "Stalwart routing verifier failed\n",
            stderr.toString(StandardCharsets.UTF_8),
        )
        assertTrue(workflow.closed)
    }

    @Test
    fun cliRedactsWorkflowFailureAndClosesIt() = runBlocking {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"
        val workflow = RecordingWorkflow(
            evidence = null,
            failure = IllegalStateException("failure carried $SECRET_CANARY"),
        )
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()

        val exitCode = StalwartRoutingProofCli(
            workflowFactory = StalwartRoutingProofWorkflowFactory { workflow },
            clock = { Instant.parse("2026-07-28T12:34:56Z") },
        ).execute(
            args = argumentsArray(dashboardRoot, invocationId),
            stdout = PrintStream(stdout, true, StandardCharsets.UTF_8),
            stderr = PrintStream(stderr, true, StandardCharsets.UTF_8),
        )

        assertEquals(1, exitCode)
        assertEquals("", stdout.toString(StandardCharsets.UTF_8))
        assertFalse(stderr.toString(StandardCharsets.UTF_8).contains(SECRET_CANARY))
        assertTrue(workflow.closed)
    }

    @Test
    fun cliPreservesCoroutineCancellationAndClosesWorkflow() = runBlocking {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"
        val workflow = RecordingWorkflow(
            evidence = null,
            failure = CancellationException("cancelled"),
        )
        val stdout = ByteArrayOutputStream()
        val stderr = ByteArrayOutputStream()

        assertFailsWith<CancellationException> {
            StalwartRoutingProofCli(
                workflowFactory =
                    StalwartRoutingProofWorkflowFactory { workflow },
            ).execute(
                args = argumentsArray(dashboardRoot, invocationId),
                stdout = PrintStream(
                    stdout,
                    true,
                    StandardCharsets.UTF_8,
                ),
                stderr = PrintStream(
                    stderr,
                    true,
                    StandardCharsets.UTF_8,
                ),
            )
        }

        assertEquals("", stdout.toString(StandardCharsets.UTF_8))
        assertEquals("", stderr.toString(StandardCharsets.UTF_8))
        assertTrue(workflow.closed)
    }

    @Test
    fun liveWorkflowUsesFixedSecretsRunsAllProbesAndCleansOwnedState() =
        runBlocking {
            val dashboardRoot = temporaryDashboardRoot()
            val invocationId = "0123456789abcdef0123456789abcdef"
            val arguments = arguments(dashboardRoot, invocationId)
            writeRoutingInput(arguments.paths.input, validInput(invocationId))
            writeSecret(
                arguments.paths.senderPassword,
                SENDER_PASSWORD,
            )
            writeSecret(
                arguments.paths.recipientPassword,
                RECIPIENT_PASSWORD,
            )
            val remote = RecordingMailRemote(invocationId)
            val workflow = StalwartRoutingLiveWorkflow(
                remoteFactory = StalwartRoutingMailRemoteFactory {
                        request,
                        input,
                    ->
                    assertEquals(
                        StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
                        request.endpointProfile,
                    )
                    assertEquals(invocationId, input.invocationId)
                    remote
                },
            )

            val evidence = workflow.prove(
                StalwartRoutingProofRequest(
                    dashboardProjectRoot = arguments.dashboardProjectRoot,
                    invocationId = invocationId,
                    endpointProfile = arguments.endpointProfile,
                    paths = arguments.paths,
                ),
            )

            assertEquals(
                listOf(
                    "enroll:sender",
                    "enroll:recipient",
                    "submit:registered_local",
                    "arrival",
                    "submit:protected_exact",
                    "submit:protected_subaddress",
                    "submit:unregistered_local",
                    "submit:external",
                    "cleanup-mail",
                    "revoke:recipient",
                    "inventory:recipient",
                    "authenticate-revoked:recipient",
                    "readiness-preflight:recipient",
                    "revoke:sender",
                    "inventory:sender",
                    "cleanup",
                ),
                remote.calls,
            )
            assertEquals(
                setOf(
                    "external",
                    "protected_exact",
                    "protected_subaddress",
                    "registered_local",
                    "unregistered_local",
                ),
                evidence.probes.keys,
            )
            assertEquals(
                "enrollmentRequired",
                evidence.recipientAccessRemoved
                    .getValue("projected_state")
                    .toString()
                    .trim('"'),
            )
            assertEquals(
                buildJsonObject {
                    put("submission_calls", 0)
                    put("upload_calls", 0)
                },
                evidence.recipientAccessRemoved
                    .getValue("readiness_preflight")
                    .jsonObject,
            )
            remote.passwordArguments.forEach { password ->
                assertContentEquals(
                    CharArray(password.size),
                    password,
                    "Workflow did not wipe a password argument",
                )
            }
            assertTrue(Files.exists(arguments.paths.input))
            assertTrue(Files.exists(arguments.paths.senderPassword))
            assertTrue(Files.exists(arguments.paths.recipientPassword))
        }

    @Test
    fun liveWorkflowRunsNonNetworkCleanupAfterProbeFailureAndWipesPasswords() =
        runBlocking {
            val dashboardRoot = temporaryDashboardRoot()
            val invocationId = "0123456789abcdef0123456789abcdef"
            val arguments = arguments(dashboardRoot, invocationId)
            writeRoutingInput(arguments.paths.input, validInput(invocationId))
            writeSecret(arguments.paths.senderPassword, SENDER_PASSWORD)
            writeSecret(arguments.paths.recipientPassword, RECIPIENT_PASSWORD)
            val remote = RecordingMailRemote(
                invocationId = invocationId,
                failAt = "submit:protected_exact",
            )
            val workflow = StalwartRoutingLiveWorkflow(
                remoteFactory = StalwartRoutingMailRemoteFactory { _, _ ->
                    remote
                },
            )

            assertFailsWith<IllegalStateException> {
                workflow.prove(
                    StalwartRoutingProofRequest(
                        dashboardProjectRoot = arguments.dashboardProjectRoot,
                        invocationId = invocationId,
                        endpointProfile = arguments.endpointProfile,
                        paths = arguments.paths,
                    ),
                )
            }

            assertTrue("cleanup" in remote.calls)
            remote.passwordArguments.forEach { password ->
                assertContentEquals(CharArray(password.size), password)
            }
        }

    @Test
    fun normalCredentialTransportNeverDispatchesMailMethods() = runBlocking {
        val dispatchedMethods = mutableListOf<String?>()
        val delegate = GateHttpTransport { request ->
            dispatchedMethods += request.body
                ?.get("methodCalls")
                ?.jsonArray
                ?.single()
                ?.jsonArray
                ?.first()
                ?.jsonPrimitive
                ?.content
            GateHttpResponse(
                status = 200,
                effectiveUrl = request.url,
                body = "{}",
            )
        }
        val transport =
            StalwartRoutingNormalCredentialTransport(delegate)
        val credential = GateCredential.basic(
            username = "dashboard-routing-sender-" +
                "0123456789abcdef0123456789abcdef@local.test",
            secret = SENDER_PASSWORD.toCharArray(),
        )
        credential.use {
            transport.execute(
                GateHttpRequest(
                    method = "GET",
                    url = URI("http://127.0.0.1:18080/.well-known/jmap"),
                    credential = credential,
                ),
            )
            assertFailsWith<IllegalArgumentException> {
                transport.execute(
                    GateHttpRequest(
                        method = "GET",
                        url = URI(
                            "http://127.0.0.1:18080/download/" +
                                "senderaccount/blob1/message.eml",
                        ),
                        credential = credential,
                    ),
                )
            }
            transport.execute(
                normalCredentialRequest(
                    credential = credential,
                    methodName = "x:AppPassword/query",
                ),
            )

            assertFailsWith<IllegalArgumentException> {
                transport.execute(
                    normalCredentialRequest(
                        credential = credential,
                        methodName = "EmailSubmission/get",
                    ),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                transport.execute(
                    normalCredentialRequest(
                        credential = credential,
                        methodName = "Email/set",
                    ),
                )
            }
        }

        assertEquals(
            listOf(null, "x:AppPassword/query"),
            dispatchedMethods,
        )
    }

    @Test
    fun routingEnrollmentClosesEachNormalCredentialClientBeforeReturning() =
        runBlocking {
            val fixture = realRemoteFixture()
            val remote = fixture.remote()
            try {
                listOf(
                    Triple(
                        StalwartRoutingActorRole.SENDER,
                        fixture.input.sender,
                        SENDER_PASSWORD,
                    ),
                    Triple(
                        StalwartRoutingActorRole.RECIPIENT,
                        fixture.input.recipient,
                        RECIPIENT_PASSWORD,
                    ),
                ).forEach { (role, actor, value) ->
                    val clear = value.toCharArray()
                    remote.enroll(
                        role = role,
                        actor = actor,
                        normalPassword = clear,
                    )

                    assertTrue(
                        fixture.transport.normalCredentialClientsClosed(
                            role.value,
                        ),
                        "Routing enrollment retained its normal credential client",
                    )
                    assertContentEquals(
                        CharArray(clear.size),
                        clear,
                        "Routing enrollment retained the request password",
                    )
                }
            } finally {
                runCatching { remote.cleanup() }
                remote.close()
            }
        }

    @Test
    fun routingRemovalReleasesMailLeaseUsesManagementAndEmptiesDurableStore() =
        runBlocking {
            val fixture = realRemoteFixture()
            val remote = fixture.remote()
            try {
                val credentialId = remote.enroll(
                    role = StalwartRoutingActorRole.SENDER,
                    actor = fixture.input.sender,
                    normalPassword = SENDER_PASSWORD.toCharArray(),
                )
                assertEquals(
                    setOf(fixture.input.sender.accountId),
                    storedAccountIds(fixture.request.dashboardProjectRoot),
                    "Routing enrollment did not capture a durable lease record",
                )

                withTimeout(2_000L) {
                    remote.revoke(
                        role = StalwartRoutingActorRole.SENDER,
                        credentialId = credentialId,
                    )
                }

                assertEquals(
                    setOf("sender"),
                    fixture.transport.managementRevokedRoles,
                )
                assertTrue(
                    fixture.transport.appCredentialClosedBeforeManagementRemoval(
                        "sender",
                    ),
                    "Routing removal reached management before releasing mail access",
                )
                assertTrue(
                    remote.appPasswordInventory(
                        StalwartRoutingActorRole.SENDER,
                    ).isEmpty(),
                )
                assertTrue(
                    storedAccountIds(fixture.request.dashboardProjectRoot).isEmpty(),
                    "Routing cleanup left a durable credential record",
                )
            } finally {
                runCatching { remote.cleanup() }
                remote.close()
            }
        }

    @Test
    fun realRoutingRemoteUsesAppPasswordsAndDefersSubmissionRemoval() =
        runBlocking {
            val fixture = realRemoteFixture()
            val readinessAccounts = mutableListOf<String>()
            val evidence = fixture.workflow(
                readinessPreflight =
                    StalwartRoutingReadinessPreflight { account ->
                        readinessAccounts += account.accountId
                        ProductionStalwartRoutingReadinessPreflight
                            .requireUnavailable(account)
                    },
            ).prove(fixture.request)

            assertEquals(
                listOf("recipientaccount"),
                readinessAccounts,
            )
            assertEquals(
                buildJsonObject {
                    put("submission_calls", 0)
                    put("upload_calls", 0)
                },
                evidence.recipientAccessRemoved
                    .getValue("readiness_preflight")
                    .jsonObject,
            )
            assertTrue(
                fixture.transport.requests
                    .filter { it.credentialKind == "normal" }
                    .all {
                        it.methodName == null ||
                            it.methodName.startsWith("x:AppPassword/")
                    },
            )
            assertTrue(
                fixture.transport.requests
                    .filter { it.credentialKind == "app" }
                    .mapNotNull(RoutingRequestRecord::methodName)
                    .toSet()
                    .containsAll(
                        setOf(
                            "Blob/upload",
                            "Email/get",
                            "Email/import",
                            "Email/query",
                            "Email/set",
                            "EmailSubmission/get",
                            "EmailSubmission/set",
                            "Identity/get",
                            "Mailbox/get",
                        ),
                    ),
            )
            assertEquals(
                5,
                fixture.transport.requests.count {
                    it.credentialKind == "app" &&
                        it.methodName == "Blob/upload"
                },
            )
            assertEquals(
                5,
                fixture.transport.requests.count {
                    it.credentialKind == "app" &&
                        it.methodName == "EmailSubmission/set" &&
                        "create" in it.arguments
                },
            )
            assertEquals(
                0,
                fixture.transport.requests.count {
                    it.methodName == "EmailSubmission/set" &&
                        "destroy" in it.arguments
                },
            )
            assertEquals(
                6,
                fixture.transport.requests.count {
                    it.credentialKind == "app" &&
                        it.methodName == "Email/set" &&
                        "destroy" in it.arguments
                },
            )
            assertEquals(5, fixture.transport.submissionCount)
            assertTrue(fixture.transport.appPasswordsRevoked())
            assertEquals(
                setOf("recipient", "sender"),
                fixture.transport.managementRevokedRoles,
            )
            assertTrue(
                storedAccountIds(fixture.request.dashboardProjectRoot)
                    .isEmpty(),
            )
        }

    @Test
    fun productionReadinessPreflightUsesTheRealNoRecordLeasePath() =
        runBlocking {
            assertEquals(
                StalwartMailAccessState.EnrollmentRequired,
                ProductionStalwartRoutingReadinessPreflight
                    .requireUnavailable(
                        StalwartMailAccount(
                            accountId = "recipientaccount",
                            address =
                                "dashboard-routing-recipient-" +
                                    "0123456789abcdef" +
                                    "0123456789abcdef@local.test",
                        ),
                    ),
            )
        }

    @Test
    fun realRoutingRemoteRejectsWrongCreateTypesAndStillRevokesActors() =
        runBlocking {
            val fixture = realRemoteFixture(
                fault = RoutingTransportFault.MALFORMED_BLOB_NOT_CREATED,
            )

            assertFailsWith<IllegalArgumentException> {
                fixture.workflow().prove(fixture.request)
            }

            assertTrue(fixture.transport.appPasswordsRevoked())
            assertEquals(
                setOf("recipient", "sender"),
                fixture.transport.revokedRoles,
            )
            assertEquals(
                setOf("recipient", "sender"),
                fixture.transport.managementRevokedRoles,
            )
            assertTrue(
                storedAccountIds(fixture.request.dashboardProjectRoot)
                    .isEmpty(),
            )
        }

    @Test
    fun realRoutingRemoteAlwaysRevokesAfterPersistentMailCleanupFailure() =
        runBlocking {
            val fixture = realRemoteFixture(
                fault = RoutingTransportFault.MALFORMED_EMAIL_DESTROY,
            )

            assertFailsWith<IllegalArgumentException> {
                fixture.workflow().prove(fixture.request)
            }

            assertTrue(fixture.transport.emailDestroyAttempts >= 6)
            assertTrue(fixture.transport.appPasswordsRevoked())
            assertEquals(
                setOf("recipient", "sender"),
                fixture.transport.revokedRoles,
            )
            assertEquals(
                setOf("recipient", "sender"),
                fixture.transport.managementRevokedRoles,
            )
            assertTrue(
                fixture.transport.postRevocationInventoryRoles
                    .containsAll(setOf("recipient", "sender")),
            )
            assertTrue(
                storedAccountIds(fixture.request.dashboardProjectRoot)
                    .isEmpty(),
            )
        }

    @Test
    fun structuralSecretAuditAllowsCredentialIdsButRejectsFieldsAndValues() {
        val forbiddenValue = SECRET_CANARY.toCharArray()
        try {
            StalwartRoutingEvidenceSecretAudit.requireSecretFree(
                value = buildJsonObject {
                    put(
                        "actor",
                        buildJsonObject {
                            put(
                                "app_password_credential_id",
                                "credential1",
                            )
                            put("credential_id", "credential2")
                        },
                    )
                },
                forbiddenValues = listOf(forbiddenValue),
            )
            assertFailsWith<IllegalArgumentException> {
                StalwartRoutingEvidenceSecretAudit.requireSecretFree(
                    value = buildJsonObject {
                        put(
                            "nested",
                            buildJsonArray {
                                add(
                                    buildJsonObject {
                                        put(
                                            "sender_password_path",
                                            "redacted",
                                        )
                                    },
                                )
                            },
                        )
                    },
                    forbiddenValues = listOf(forbiddenValue),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                StalwartRoutingEvidenceSecretAudit.requireSecretFree(
                    value = buildJsonObject {
                        put(
                            "nested",
                            buildJsonArray {
                                add(JsonPrimitive(SECRET_CANARY))
                            },
                        )
                    },
                    forbiddenValues = listOf(forbiddenValue),
                )
            }
        } finally {
            forbiddenValue.fill('\u0000')
        }
    }

    @Test
    fun submissionNormalizerUsesOnlySourceDefinedRecipientStatus() {
        val invocationId = "0123456789abcdef0123456789abcdef"
        val registered = StalwartRoutingProbeSpec(
            name = "registered_local",
            recipient =
                "dashboard-routing-recipient-$invocationId@local.test",
            enhancedStatus = "2.1.5",
            registeredLocal = true,
        )
        val rejected = StalwartRoutingProbeSpec(
            name = "protected_exact",
            recipient = "dashboard-management@local.test",
            enhancedStatus = "5.7.1",
            registeredLocal = false,
        )

        assertEquals(
            buildJsonObject {
                put("delivery_status", "unknown")
                put("enhanced_status", "2.1.5")
                put("queue_accepted", true)
                put("recipient", registered.recipient)
                put("smtp_code", 250)
                put("submission_created", true)
                put("submission_id", "submission1")
                put("undo_status", "final")
            },
            StalwartRoutingSubmissionNormalizer.normalize(
                probe = registered,
                submissionId = "submission1",
                undoStatus = "final",
                deliveryStatus = deliveryStatus(
                    recipient = registered.recipient,
                    delivered = "unknown",
                    smtpReply = "250 2.1.5 Queued",
                ),
            ),
        )
        assertEquals(
            buildJsonObject {
                put("delivery_status", "no")
                put("enhanced_status", "5.7.1")
                put("queue_accepted", false)
                put("recipient", rejected.recipient)
                put("smtp_code", 550)
                put("submission_created", true)
                put("submission_id", "submission2")
                put("undo_status", "pending")
            },
            StalwartRoutingSubmissionNormalizer.normalize(
                probe = rejected,
                submissionId = "submission2",
                undoStatus = "pending",
                deliveryStatus = deliveryStatus(
                    recipient = rejected.recipient,
                    delivered = "no",
                    smtpReply = "550 5.7.1 Recipient is reserved",
                ),
            ),
        )
        assertFailsWith<IllegalArgumentException> {
            StalwartRoutingSubmissionNormalizer.normalize(
                probe = registered,
                submissionId = "submission3",
                undoStatus = "final",
                deliveryStatus = deliveryStatus(
                    recipient = registered.recipient,
                    delivered = "yes",
                    smtpReply = "250 2.0.0 Delivered",
                ),
            )
        }
    }

    private fun validEvidence(invocationId: String): StalwartRoutingVerifierEvidence {
        val senderAddress =
            "dashboard-routing-sender-$invocationId@local.test"
        val recipientAddress =
            "dashboard-routing-recipient-$invocationId@local.test"
        val messageId = "<mail-sandbox-routing-$invocationId@local.test>"
        fun rejection(
            recipient: String,
            submissionId: String,
            enhancedStatus: String,
        ): JsonObject = buildJsonObject {
            put("delivery_status", "no")
            put("enhanced_status", enhancedStatus)
            put("queue_accepted", false)
            put("recipient", recipient)
            put("smtp_code", 550)
            put("submission_created", true)
            put("submission_id", submissionId)
            put("undo_status", "pending")
        }
        return StalwartRoutingVerifierEvidence(
            serverVersion = "0.16.14",
            managementAccountId = "managementaccount",
            managementCredentialId = "managementcredential",
            bootstrapProof = bootstrapProof(),
            preservedObjectsSha256 = "a".repeat(64),
            sender = StalwartRoutingActorEvidence(
                accountId = "senderaccount",
                address = senderAddress,
                appPasswordCredentialId = "senderapppassword",
            ),
            recipient = StalwartRoutingActorEvidence(
                accountId = "recipientaccount",
                address = recipientAddress,
                appPasswordCredentialId = "recipientapppassword",
            ),
            messageId = messageId,
            probes = mapOf(
                "registered_local" to buildJsonObject {
                    put(
                        "arrival",
                        buildJsonObject {
                            put("account_id", "recipientaccount")
                            put(
                                "matching_email_ids",
                                buildJsonArray {
                                    add(JsonPrimitive("recipientemail"))
                                },
                            )
                            put("message_id", messageId)
                        },
                    )
                    put("delivery_status", "unknown")
                    put("enhanced_status", "2.1.5")
                    put("queue_accepted", true)
                    put("recipient", recipientAddress)
                    put("smtp_code", 250)
                    put("submission_created", true)
                    put("submission_id", "registeredsubmission")
                    put("undo_status", "final")
                },
                "protected_exact" to rejection(
                    "dashboard-management@local.test",
                    "protectedexactsubmission",
                    "5.7.1",
                ),
                "protected_subaddress" to rejection(
                    "dashboard-management+routing-$invocationId@local.test",
                    "protectedsubaddresssubmission",
                    "5.7.1",
                ),
                "unregistered_local" to rejection(
                    "dashboard-routing-missing-$invocationId@local.test",
                    "unregisteredsubmission",
                    "5.1.2",
                ),
                "external" to rejection(
                    "dashboard-routing-$invocationId@example.invalid",
                    "externalsubmission",
                    "5.1.2",
                ),
            ),
            recipientAccessRemoved = buildJsonObject {
                put("authentication_status", 401)
                put("credential_id", "recipientapppassword")
                put("projected_state", "enrollmentRequired")
                put(
                    "readiness_preflight",
                    buildJsonObject {
                        put("submission_calls", 0)
                        put("upload_calls", 0)
                    },
                )
            },
        )
    }

    private fun deliveryStatus(
        recipient: String,
        delivered: String,
        smtpReply: String,
    ): JsonObject = buildJsonObject {
        put(
            recipient,
            buildJsonObject {
                put("delivered", delivered)
                put("displayed", "unknown")
                put("smtpReply", smtpReply)
            },
        )
    }

    private fun validInput(invocationId: String): JsonObject =
        buildJsonObject {
            put(
                "actors",
                buildJsonObject {
                    put(
                        "recipient",
                        buildJsonObject {
                            put("account_id", "recipientaccount")
                            put(
                                "address",
                                "dashboard-routing-recipient-$invocationId@local.test",
                            )
                        },
                    )
                    put(
                        "sender",
                        buildJsonObject {
                            put("account_id", "senderaccount")
                            put(
                                "address",
                                "dashboard-routing-sender-$invocationId@local.test",
                            )
                        },
                    )
                },
            )
            put("bootstrap_proof", bootstrapProof())
            put("invocation_id", invocationId)
            put("management_account_id", "managementaccount")
            put("management_credential_id", "managementcredential")
            put("preserved_objects_sha256", "a".repeat(64))
            put(
                "schema",
                "mail-sandbox.stalwart-v016-routing-input.v1",
            )
            put("server_version", "0.16.14")
        }

    private fun bootstrapProof(): JsonObject = buildJsonObject {
        put(
            "identity",
            JsonArray((1L..6L).map(::JsonPrimitive)),
        )
        put("name", "bootstrap-proof.json")
        put("sha256", "b".repeat(64))
        put("size", 123)
    }

    private fun writeRoutingInput(path: Path, value: JsonObject) {
        path.parent.createDirectories()
        Files.setPosixFilePermissions(
            path.parent,
            PosixFilePermissions.fromString("rwx------"),
        )
        path.writeText(canonicalJson(value) + "\n")
        Files.setPosixFilePermissions(
            path,
            PosixFilePermissions.fromString("rw-------"),
        )
    }

    private fun writeSecret(path: Path, value: String) {
        path.parent.createDirectories()
        Files.setPosixFilePermissions(
            path.parent,
            PosixFilePermissions.fromString("rwx------"),
        )
        path.writeText(value)
        Files.setPosixFilePermissions(
            path,
            PosixFilePermissions.fromString("rw-------"),
        )
    }

    private fun writeRuntimeManagementMaterial(dashboardRoot: Path) {
        val runtime = dashboardRoot.resolve(".runtime")
        val secrets = runtime.resolve("secrets")
        val stalwart = runtime.resolve("stalwart")
        runtime.createDirectories()
        secrets.createDirectories()
        stalwart.createDirectories()
        listOf(runtime, secrets, stalwart).forEach { directory ->
            Files.setPosixFilePermissions(
                directory,
                PosixFilePermissions.fromString("rwx------"),
            )
        }
        writeSecret(
            secrets.resolve("stalwart-management-api-key"),
            MANAGEMENT_API_KEY,
        )
        writeSecret(
            stalwart.resolve("protected-accounts.json"),
            """{"account_ids":["managementaccount"],""" +
                """"schema":"mail-sandbox.stalwart-v016-protected-accounts.v1"}""" +
                "\n",
        )
    }

    private fun storedAccountIds(dashboardRoot: Path): Set<String> {
        val store = FileStalwartCredentialStore(
            CredentialStorePaths.production(dashboardRoot),
        )
        return try {
            when (val loaded = store.load()) {
                is CredentialStoreLoadResult.Available ->
                    loaded.snapshot.use { it.records.keys.toSet() }
                CredentialStoreLoadResult.StoreUnavailable ->
                    error("Routing credential store was unavailable")
            }
        } finally {
            store.close()
        }
    }

    private fun canonicalJson(value: JsonObject): String =
        StalwartRoutingCanonicalJson.encode(value)

    private fun arguments(
        dashboardRoot: Path,
        invocationId: String,
    ): StalwartRoutingProofArguments =
        StalwartRoutingProofArguments.parse(
            argumentsArray(dashboardRoot, invocationId),
        )

    private fun argumentsArray(
        dashboardRoot: Path,
        invocationId: String,
    ): Array<String> = arrayOf(
        "--dashboard-project-root",
        dashboardRoot.toString(),
        "--invocation-id",
        invocationId,
    )

    private fun temporaryDashboardRoot(): Path {
        val root = Files.createTempDirectory("stalwart-routing-cli-")
            .toRealPath()
            .resolve("debug-dashboard")
        root.createDirectories()
        root.resolve("project.yaml").writeText("modules: []\n")
        return root
    }

    private fun normalCredentialRequest(
        credential: GateCredential,
        methodName: String,
    ): GateHttpRequest = GateHttpRequest(
        method = "POST",
        url = URI("http://127.0.0.1:18080/jmap/"),
        credential = credential,
        body = buildJsonObject {
            put(
                "using",
                buildJsonArray {
                    add(JsonPrimitive("urn:ietf:params:jmap:core"))
                    add(JsonPrimitive("urn:stalwart:jmap"))
                },
            )
            put(
                "methodCalls",
                buildJsonArray {
                    add(
                        buildJsonArray {
                            add(JsonPrimitive(methodName))
                            add(buildJsonObject {})
                            add(JsonPrimitive("gate-1"))
                        },
                    )
                },
            )
        },
    )

    private fun realRemoteFixture(
        fault: RoutingTransportFault = RoutingTransportFault.NONE,
    ): RealRemoteFixture {
        val dashboardRoot = temporaryDashboardRoot()
        val invocationId = "0123456789abcdef0123456789abcdef"
        val arguments = arguments(dashboardRoot, invocationId)
        writeRoutingInput(arguments.paths.input, validInput(invocationId))
        writeSecret(arguments.paths.senderPassword, SENDER_PASSWORD)
        writeSecret(arguments.paths.recipientPassword, RECIPIENT_PASSWORD)
        writeRuntimeManagementMaterial(dashboardRoot)
        val input = StalwartRoutingProofInputFiles.read(arguments)
        return RealRemoteFixture(
            request = StalwartRoutingProofRequest(
                dashboardProjectRoot = arguments.dashboardProjectRoot,
                invocationId = invocationId,
                endpointProfile = arguments.endpointProfile,
                paths = arguments.paths,
            ),
            input = input,
            transport = ScriptedRoutingTransport(
                invocationId = invocationId,
                fault = fault,
            ),
        )
    }

    private data class RealRemoteFixture(
        val request: StalwartRoutingProofRequest,
        val input: StalwartRoutingProofInput,
        val transport: ScriptedRoutingTransport,
    ) {
        fun remote(): KtorStalwartRoutingMailRemote =
            KtorStalwartRoutingMailRemote(
                request = request,
                input = input,
                transport = transport,
            )

        fun workflow(
            readinessPreflight: StalwartRoutingReadinessPreflight =
                ProductionStalwartRoutingReadinessPreflight,
        ): StalwartRoutingLiveWorkflow =
            StalwartRoutingLiveWorkflow(
                remoteFactory =
                    StalwartRoutingMailRemoteFactory { request, input ->
                        KtorStalwartRoutingMailRemote(
                            request = request,
                            input = input,
                            transport = transport,
                            readinessPreflight = readinessPreflight,
                        )
                    },
            )
    }

    private enum class RoutingTransportFault {
        NONE,
        MALFORMED_BLOB_NOT_CREATED,
        MALFORMED_EMAIL_DESTROY,
    }

    private data class RoutingRequestRecord(
        val role: String,
        val credentialKind: String,
        val methodName: String?,
        val arguments: JsonObject,
    )

    private class ScriptedRoutingTransport(
        invocationId: String,
        private val fault: RoutingTransportFault,
    ) : GateHttpTransport {
        private val actors = linkedMapOf(
            "sender" to RoutingActorState(
                role = "sender",
                accountId = "senderaccount",
                address =
                    "dashboard-routing-sender-$invocationId@local.test",
                normalPassword = SENDER_PASSWORD,
                appPasswordId = "sendercredential",
                appPassword = "app_sender_routing_test",
            ),
            "recipient" to RoutingActorState(
                role = "recipient",
                accountId = "recipientaccount",
                address =
                    "dashboard-routing-recipient-$invocationId@local.test",
                normalPassword = RECIPIENT_PASSWORD,
                appPasswordId = "recipientcredential",
                appPassword = "app_recipient_routing_test",
            ),
        )
        private val blobs = linkedMapOf<String, RoutingMessage>()
        private val emails = linkedMapOf<String, RoutingEmail>()
        private val submissions = linkedMapOf<String, RoutingSubmission>()
        private var blobSequence = 0
        private var emailSequence = 0
        private var submissionSequence = 0

        val requests = mutableListOf<RoutingRequestRecord>()
        val revokedRoles = linkedSetOf<String>()
        val postRevocationInventoryRoles = linkedSetOf<String>()
        val managementRevokedRoles = linkedSetOf<String>()
        private val normalCredentials =
            linkedMapOf<String, MutableSet<GateCredential>>()
        private val appCredentials =
            linkedMapOf<String, MutableSet<GateCredential>>()
        var emailDestroyAttempts = 0
            private set

        val submissionCount: Int
            get() = submissions.size

        fun appPasswordsRevoked(): Boolean =
            actors.values.all { !it.appPasswordActive }

        fun normalCredentialClientsClosed(role: String): Boolean =
            normalCredentials[role]
                ?.takeIf { it.isNotEmpty() }
                ?.all { credential ->
                    runCatching { credential.authorizationHeader() }.isFailure
                } == true

        fun appCredentialClosedBeforeManagementRemoval(role: String): Boolean =
            role in managementRevokedRoles &&
                appCredentials[role]
                    ?.takeIf { it.isNotEmpty() }
                    ?.all { credential ->
                        runCatching {
                            credential.authorizationHeader()
                        }.isFailure
                    } == true

        override suspend fun execute(
            request: GateHttpRequest,
        ): GateHttpResponse {
            if (
                request.credential.authorizationHeader() ==
                bearerAuthorization(MANAGEMENT_API_KEY)
            ) {
                return management(request)
            }
            val credential = credential(request)
            if (
                request.method == "GET" &&
                credential.kind == "app" &&
                !credential.actor.appPasswordActive
            ) {
                return GateHttpResponse(
                    status = 401,
                    effectiveUrl = request.url,
                    body = "{}",
                )
            }
            if (request.method == "GET") {
                requests += RoutingRequestRecord(
                    role = credential.actor.role,
                    credentialKind = credential.kind,
                    methodName = null,
                    arguments = buildJsonObject {},
                )
                return GateHttpResponse(
                    status = 200,
                    effectiveUrl = request.url,
                    body = session(credential.actor).toString(),
                )
            }
            val tuple = requireNotNull(request.body)
                .getValue("methodCalls")
                .jsonArray
                .single()
                .jsonArray
            val methodName = tuple[0].jsonPrimitive.content
            val arguments = tuple[1].jsonObject
            val callId = tuple[2].jsonPrimitive.content
            requests += RoutingRequestRecord(
                role = credential.actor.role,
                credentialKind = credential.kind,
                methodName = methodName,
                arguments = arguments,
            )
            val payload = when {
                methodName.startsWith("x:AppPassword/") ->
                    appPassword(
                        actor = credential.actor,
                        methodName = methodName,
                        arguments = arguments,
                    )

                else -> {
                    require(credential.kind == "app") {
                        "Normal credential reached a mail method"
                    }
                    mail(
                        actor = credential.actor,
                        methodName = methodName,
                        arguments = arguments,
                    )
                }
            }
            return GateHttpResponse(
                status = 200,
                effectiveUrl = request.url,
                body = methodResponse(
                    methodName = methodName,
                    callId = callId,
                    payload = payload,
                ).toString(),
            )
        }

        private fun management(
            request: GateHttpRequest,
        ): GateHttpResponse {
            if (request.method == "GET") {
                requests += RoutingRequestRecord(
                    role = "management",
                    credentialKind = "management",
                    methodName = null,
                    arguments = buildJsonObject {},
                )
                return GateHttpResponse(
                    status = 200,
                    effectiveUrl = request.url,
                    body = managementSession().toString(),
                )
            }
            val tuple = requireNotNull(request.body)
                .getValue("methodCalls")
                .jsonArray
                .single()
                .jsonArray
            val methodName = tuple[0].jsonPrimitive.content
            val arguments = tuple[1].jsonObject
            val callId = tuple[2].jsonPrimitive.content
            requests += RoutingRequestRecord(
                role = "management",
                credentialKind = "management",
                methodName = methodName,
                arguments = arguments,
            )
            val payload = when (methodName) {
                "x:Account/get" -> managementAccountGet(arguments)
                "x:Account/query" -> managementAccountQuery()
                "x:Account/set" -> managementAccountSet(arguments)
                else -> error("Unsupported management method $methodName")
            }
            return GateHttpResponse(
                status = 200,
                effectiveUrl = request.url,
                body = methodResponse(
                    methodName = methodName,
                    callId = callId,
                    payload = payload,
                ).toString(),
            )
        }

        private fun managementSession(): JsonObject =
            buildJsonObject {
                put(
                    "apiUrl",
                    StalwartEndpointProfile.MIGRATION_BOOTSTRAP
                        .apiUrl
                        .toString(),
                )
                put("username", GateBootstrap.MANAGEMENT_ADDRESS)
                put(
                    "primaryAccounts",
                    buildJsonObject {
                        put("urn:stalwart:jmap", "managementaccount")
                    },
                )
            }

        private fun managementAccountQuery(): JsonObject =
            buildJsonObject {
                put("accountId", "managementaccount")
                put("queryState", "management-query-state")
                put("canCalculateChanges", false)
                put("position", 0)
                put(
                    "ids",
                    buildJsonArray {
                        add(JsonPrimitive("managementaccount"))
                        actors.values.forEach {
                            add(JsonPrimitive(it.accountId))
                        }
                    },
                )
                put("total", actors.size + 1)
            }

        private fun managementAccountGet(
            arguments: JsonObject,
        ): JsonObject {
            val ids = arguments.getValue("ids").jsonArray.map {
                it.jsonPrimitive.content
            }
            val objects = ids.map { accountId ->
                if (accountId == "managementaccount") {
                    managementAccountObject()
                } else {
                    actorAccountObject(
                        actors.values.single {
                            it.accountId == accountId
                        },
                    )
                }
            }
            return buildJsonObject {
                put("accountId", "managementaccount")
                put("state", "management-account-state")
                put("list", JsonArray(objects))
                put("notFound", buildJsonArray {})
            }
        }

        private fun managementAccountSet(
            arguments: JsonObject,
        ): JsonObject {
            val updates = arguments.getValue("update").jsonObject
            require(updates.size == 1)
            val (accountId, patchValue) = updates.entries.single()
            val actor = actors.values.single { it.accountId == accountId }
            val patch = patchValue.jsonObject
            require(
                patch.isNotEmpty() &&
                    patch.all { (path, value) ->
                        path == "credentials/17" && value == JsonNull
                    },
            )
            require(actor.appPasswordActive)
            actor.appPasswordActive = false
            managementRevokedRoles += actor.role
            revokedRoles += actor.role
            return buildJsonObject {
                put("accountId", "managementaccount")
                put(
                    "updated",
                    buildJsonObject {
                        put(accountId, JsonNull)
                    },
                )
                put("notUpdated", buildJsonObject {})
            }
        }

        private fun managementAccountObject(): JsonObject =
            buildJsonObject {
                put("id", "managementaccount")
                put(
                    "credentials",
                    buildJsonObject {
                        put(
                            "0",
                            buildJsonObject {
                                put("@type", "ApiKey")
                                put(
                                    "credentialId",
                                    "managementcredential",
                                )
                            },
                        )
                    },
                )
                put(
                    "quotas",
                    buildJsonObject {
                        put("maxAppPasswords", 2)
                    },
                )
            }

        private fun actorAccountObject(
            actor: RoutingActorState,
        ): JsonObject {
            if (!actor.appPasswordActive && actor.everCreated) {
                postRevocationInventoryRoles += actor.role
            }
            return buildJsonObject {
                put("id", actor.accountId)
                put(
                    "credentials",
                    buildJsonObject {
                        put(
                            "0",
                            buildJsonObject {
                                put("@type", "Password")
                                put(
                                    "credentialId",
                                    "${actor.role}password",
                                )
                            },
                        )
                        if (actor.appPasswordActive) {
                            put(
                                "17",
                                buildJsonObject {
                                    put("@type", "AppPassword")
                                    put(
                                        "credentialId",
                                        actor.appPasswordId,
                                    )
                                    put(
                                        "description",
                                        requireNotNull(actor.description),
                                    )
                                },
                            )
                        }
                    },
                )
                put(
                    "quotas",
                    buildJsonObject {
                        put("maxAppPasswords", 2)
                    },
                )
            }
        }

        private fun credential(
            request: GateHttpRequest,
        ): RoutingCredential {
            val authorization = request.credential.authorizationHeader()
            actors.values.forEach { actor ->
                if (
                    authorization ==
                    basicAuthorization(actor.address, actor.normalPassword)
                ) {
                    normalCredentials
                        .getOrPut(actor.role) { linkedSetOf() }
                        .add(request.credential)
                    return RoutingCredential(actor, "normal")
                }
                if (
                    authorization ==
                    basicAuthorization(actor.address, actor.appPassword)
                ) {
                    appCredentials
                        .getOrPut(actor.role) { linkedSetOf() }
                        .add(request.credential)
                    return RoutingCredential(actor, "app")
                }
            }
            throw IllegalArgumentException("Unknown routing credential")
        }

        private fun session(actor: RoutingActorState): JsonObject =
            buildJsonObject {
                put(
                    "apiUrl",
                    StalwartEndpointProfile.MIGRATION_BOOTSTRAP
                        .apiUrl
                        .toString(),
                )
                put("username", actor.address)
                put(
                    "primaryAccounts",
                    buildJsonObject {
                        put("urn:stalwart:jmap", actor.accountId)
                    },
                )
            }

        private fun appPassword(
            actor: RoutingActorState,
            methodName: String,
            arguments: JsonObject,
        ): JsonObject = when (methodName) {
            "x:AppPassword/query" -> {
                if (!actor.appPasswordActive && actor.everCreated) {
                    postRevocationInventoryRoles += actor.role
                }
                buildJsonObject {
                    put("accountId", actor.accountId)
                    put("queryState", "state-${actor.role}")
                    put("canCalculateChanges", false)
                    put("position", 0)
                    put(
                        "ids",
                        if (actor.appPasswordActive) {
                            buildJsonArray {
                                add(JsonPrimitive(actor.appPasswordId))
                            }
                        } else {
                            buildJsonArray {}
                        },
                    )
                    put("total", if (actor.appPasswordActive) 1 else 0)
                }
            }

            "x:AppPassword/get" -> buildJsonObject {
                put("accountId", actor.accountId)
                put("state", "state-${actor.role}")
                put(
                    "list",
                    if (actor.appPasswordActive) {
                        buildJsonArray {
                            add(
                                buildJsonObject {
                                    put("id", actor.appPasswordId)
                                    put(
                                        "description",
                                        requireNotNull(actor.description),
                                    )
                                    put("secret", "****")
                                    put(
                                        "permissions",
                                        buildJsonObject {
                                            put("@type", "Replace")
                                            put(
                                                "permissions",
                                                buildJsonObject {
                                                    DASHBOARD_MAIL_PERMISSIONS
                                                        .forEach {
                                                            put(it, true)
                                                        }
                                                },
                                            )
                                        },
                                    )
                                    put(
                                        "allowedIps",
                                        buildJsonObject {},
                                    )
                                },
                            )
                        }
                    } else {
                        buildJsonArray {}
                    },
                )
                put("notFound", buildJsonArray {})
            }

            "x:AppPassword/set" -> {
                when {
                    "create" in arguments -> {
                        val create = arguments
                            .getValue("create")
                            .jsonObject
                            .getValue("dashboard-app-password")
                            .jsonObject
                        actor.description = create
                            .getValue("description")
                            .jsonPrimitive
                            .content
                        actor.appPasswordActive = true
                        actor.everCreated = true
                        buildJsonObject {
                            put("accountId", actor.accountId)
                            put(
                                "created",
                                buildJsonObject {
                                    put(
                                        "dashboard-app-password",
                                        buildJsonObject {
                                            put(
                                                "id",
                                                actor.appPasswordId,
                                            )
                                            put(
                                                "secret",
                                                actor.appPassword,
                                            )
                                        },
                                    )
                                },
                            )
                            put("notCreated", buildJsonObject {})
                        }
                    }

                    "destroy" in arguments -> {
                        val id = arguments
                            .getValue("destroy")
                            .jsonArray
                            .single()
                            .jsonPrimitive
                            .content
                        require(id == actor.appPasswordId)
                        actor.appPasswordActive = false
                        revokedRoles += actor.role
                        buildJsonObject {
                            put("accountId", actor.accountId)
                            put(
                                "destroyed",
                                buildJsonArray {
                                    add(JsonPrimitive(id))
                                },
                            )
                            put("notDestroyed", buildJsonObject {})
                        }
                    }

                    else -> error("Unsupported AppPassword mutation")
                }
            }

            else -> error("Unsupported AppPassword method")
        }

        private fun mail(
            actor: RoutingActorState,
            methodName: String,
            arguments: JsonObject,
        ): JsonObject = when (methodName) {
            "Core/echo" -> arguments

            "Mailbox/get" -> buildJsonObject {
                put("accountId", actor.accountId)
                put(
                    "list",
                    buildJsonArray {
                        add(
                            buildJsonObject {
                                put("id", "${actor.role}drafts")
                                put("role", "drafts")
                            },
                        )
                    },
                )
                put("notFound", buildJsonArray {})
            }

            "Identity/get" -> buildJsonObject {
                put("accountId", actor.accountId)
                put(
                    "list",
                    buildJsonArray {
                        add(
                            buildJsonObject {
                                put("id", "${actor.role}identity")
                                put("email", actor.address)
                            },
                        )
                    },
                )
                put("notFound", buildJsonArray {})
            }

            "Blob/upload" -> upload(arguments)
            "Blob/get" -> absentProbeGet(actor, arguments)
            "Email/import" -> importEmail(actor, arguments)
            "EmailSubmission/set" ->
                createSubmission(actor, arguments)
            "EmailSubmission/get" ->
                if (arguments.isAbsentProbeGet()) {
                    absentProbeGet(actor, arguments)
                } else {
                    getSubmissions(actor, arguments)
                }
            "Email/query" -> queryEmail(actor, arguments)
            "Email/get" -> getEmail(actor, arguments)
            "Email/set" -> destroyEmail(arguments)
            else -> error("Unsupported routing mail method $methodName")
        }

        private fun JsonObject.isAbsentProbeGet(): Boolean =
            (this["ids"] as? JsonArray)?.map {
                it.jsonPrimitive.content
            } == listOf("mailSandboxProbeAbsent")

        private fun absentProbeGet(
            actor: RoutingActorState,
            arguments: JsonObject,
        ): JsonObject {
            require(arguments.isAbsentProbeGet())
            return buildJsonObject {
                put("accountId", actor.accountId)
                put("list", buildJsonArray {})
                put(
                    "notFound",
                    buildJsonArray {
                        add(JsonPrimitive("mailSandboxProbeAbsent"))
                    },
                )
            }
        }

        private fun upload(arguments: JsonObject): JsonObject {
            val value = arguments
                .getValue("create")
                .jsonObject
                .getValue("routing-blob")
                .jsonObject
            val message = value
                .getValue("data")
                .jsonArray
                .single()
                .jsonObject
                .getValue("data:asText")
                .jsonPrimitive
                .content
            val blobId = "blob${++blobSequence}"
            blobs[blobId] = parseMessage(message)
            return buildJsonObject {
                put(
                    "created",
                    buildJsonObject {
                        put(
                            "routing-blob",
                            buildJsonObject {
                                put("id", blobId)
                                put("type", "message/rfc822")
                            },
                        )
                    },
                )
                if (
                    fault ==
                    RoutingTransportFault.MALFORMED_BLOB_NOT_CREATED
                ) {
                    put("notCreated", buildJsonArray {})
                } else {
                    put("notCreated", buildJsonObject {})
                }
            }
        }

        private fun importEmail(
            actor: RoutingActorState,
            arguments: JsonObject,
        ): JsonObject {
            val blobId = arguments
                .getValue("emails")
                .jsonObject
                .getValue("routing-email")
                .jsonObject
                .getValue("blobId")
                .jsonPrimitive
                .content
            val message = requireNotNull(blobs[blobId])
            val emailId = "senderemail${++emailSequence}"
            emails[emailId] = RoutingEmail(
                id = emailId,
                role = actor.role,
                message = message,
            )
            return oneCreated("routing-email", emailId)
        }

        private fun createSubmission(
            actor: RoutingActorState,
            arguments: JsonObject,
        ): JsonObject {
            require("destroy" !in arguments) {
                "Kotlin attempted forbidden EmailSubmission destroy"
            }
            val value = arguments
                .getValue("create")
                .jsonObject
                .getValue("routing-submission")
                .jsonObject
            val emailId = value
                .getValue("emailId")
                .jsonPrimitive
                .content
            val recipient = value
                .getValue("envelope")
                .jsonObject
                .getValue("rcptTo")
                .jsonArray
                .single()
                .jsonObject
                .getValue("email")
                .jsonPrimitive
                .content
            val submissionId =
                "submission${++submissionSequence}"
            submissions[submissionId] = RoutingSubmission(
                id = submissionId,
                emailId = emailId,
                recipient = recipient,
            )
            val recipientActor = actors.getValue("recipient")
            if (recipient == recipientActor.address) {
                val source = requireNotNull(emails[emailId])
                val recipientEmailId = "recipientemail"
                emails[recipientEmailId] = RoutingEmail(
                    id = recipientEmailId,
                    role = recipientActor.role,
                    message = source.message,
                )
            }
            return oneCreated("routing-submission", submissionId)
        }

        private fun getSubmissions(
            actor: RoutingActorState,
            arguments: JsonObject,
        ): JsonObject {
            require(actor.role == "sender")
            val ids = arguments["ids"]
            val selected = if (ids == null || ids == JsonNull) {
                submissions.values.toList()
            } else {
                ids.jsonArray.map {
                    requireNotNull(
                        submissions[it.jsonPrimitive.content],
                    )
                }
            }
            return buildJsonObject {
                put("accountId", actor.accountId)
                put(
                    "list",
                    buildJsonArray {
                        selected.forEach { submission ->
                            add(
                                if (ids == null || ids == JsonNull) {
                                    buildJsonObject {
                                        put("id", submission.id)
                                        put(
                                            "emailId",
                                            submission.emailId,
                                        )
                                    }
                                } else {
                                    submissionStatus(submission)
                                },
                            )
                        }
                    },
                )
                put("notFound", buildJsonArray {})
            }
        }

        private fun submissionStatus(
            submission: RoutingSubmission,
        ): JsonObject {
            val registered =
                submission.recipient == actors.getValue("recipient").address
            val enhanced = when {
                registered -> "2.1.5"
                submission.recipient.startsWith(
                    "dashboard-management",
                ) -> "5.7.1"
                else -> "5.1.2"
            }
            return buildJsonObject {
                put("id", submission.id)
                put("undoStatus", if (registered) "final" else "pending")
                put(
                    "deliveryStatus",
                    buildJsonObject {
                        put(
                            submission.recipient,
                            buildJsonObject {
                                put(
                                    "delivered",
                                    if (registered) "unknown" else "no",
                                )
                                put("displayed", "unknown")
                                put(
                                    "smtpReply",
                                    if (registered) {
                                        "250 2.1.5 Queued"
                                    } else {
                                        "550 $enhanced Rejected"
                                    },
                                )
                            },
                        )
                    },
                )
            }
        }

        private fun queryEmail(
            actor: RoutingActorState,
            arguments: JsonObject,
        ): JsonObject {
            val subject = arguments
                .getValue("filter")
                .jsonObject
                .getValue("subject")
                .jsonPrimitive
                .content
            val ids = emails.values
                .filter {
                    !it.deleted &&
                        it.role == actor.role &&
                        it.message.subject == subject
                }
                .map(RoutingEmail::id)
            return buildJsonObject {
                put("accountId", actor.accountId)
                put("queryState", "email-state")
                put("canCalculateChanges", false)
                put("position", 0)
                put(
                    "ids",
                    buildJsonArray {
                        ids.forEach { add(JsonPrimitive(it)) }
                    },
                )
                put("total", ids.size)
            }
        }

        private fun getEmail(
            actor: RoutingActorState,
            arguments: JsonObject,
        ): JsonObject {
            val id = arguments
                .getValue("ids")
                .jsonArray
                .single()
                .jsonPrimitive
                .content
            val email = requireNotNull(emails[id])
            require(email.role == actor.role && !email.deleted)
            return buildJsonObject {
                put("accountId", actor.accountId)
                put(
                    "list",
                    buildJsonArray {
                        add(
                            buildJsonObject {
                                put("id", id)
                                put("subject", email.message.subject)
                                put(
                                    "messageId",
                                    buildJsonArray {
                                        add(
                                            JsonPrimitive(
                                                email.message.messageId
                                                    .removePrefix("<")
                                                    .removeSuffix(">"),
                                            ),
                                        )
                                    },
                                )
                            },
                        )
                    },
                )
                put("notFound", buildJsonArray {})
            }
        }

        private fun destroyEmail(
            arguments: JsonObject,
        ): JsonObject {
            emailDestroyAttempts += 1
            val id = arguments
                .getValue("destroy")
                .jsonArray
                .single()
                .jsonPrimitive
                .content
            if (
                fault ==
                RoutingTransportFault.MALFORMED_EMAIL_DESTROY
            ) {
                return buildJsonObject {
                    put("destroyed", "wrong-type")
                    put("notDestroyed", buildJsonObject {})
                }
            }
            requireNotNull(emails[id]).deleted = true
            return buildJsonObject {
                put(
                    "destroyed",
                    buildJsonArray { add(JsonPrimitive(id)) },
                )
                put("notDestroyed", buildJsonObject {})
            }
        }

        private fun oneCreated(
            creationId: String,
            id: String,
        ): JsonObject = buildJsonObject {
            put(
                "created",
                buildJsonObject {
                    put(
                        creationId,
                        buildJsonObject { put("id", id) },
                    )
                },
            )
            put("notCreated", buildJsonObject {})
        }

        private fun methodResponse(
            methodName: String,
            callId: String,
            payload: JsonObject,
        ): JsonObject = buildJsonObject {
            put(
                "methodResponses",
                buildJsonArray {
                    add(
                        buildJsonArray {
                            add(JsonPrimitive(methodName))
                            add(payload)
                            add(JsonPrimitive(callId))
                        },
                    )
                },
            )
        }

        private fun parseMessage(value: String): RoutingMessage {
            val headers = value
                .substringBefore("\r\n\r\n")
                .split("\r\n")
                .associate {
                    val separator = it.indexOf(':')
                    require(separator > 0)
                    it.substring(0, separator) to
                        it.substring(separator + 1).trim()
                }
            return RoutingMessage(
                subject = requireNotNull(headers["Subject"]),
                messageId = requireNotNull(headers["Message-ID"]),
            )
        }

        private fun basicAuthorization(
            username: String,
            secret: String,
        ): String {
            val value = "$username:$secret"
                .toByteArray(StandardCharsets.UTF_8)
            return try {
                "Basic " +
                    Base64.getEncoder().encodeToString(value)
            } finally {
                value.fill(0)
            }
        }

        private fun bearerAuthorization(secret: String): String =
            "Bearer $secret"
    }

    private data class RoutingActorState(
        val role: String,
        val accountId: String,
        val address: String,
        val normalPassword: String,
        val appPasswordId: String,
        val appPassword: String,
        var appPasswordActive: Boolean = false,
        var everCreated: Boolean = false,
        var description: String? = null,
    )

    private data class RoutingCredential(
        val actor: RoutingActorState,
        val kind: String,
    )

    private data class RoutingMessage(
        val subject: String,
        val messageId: String,
    )

    private data class RoutingEmail(
        val id: String,
        val role: String,
        val message: RoutingMessage,
        var deleted: Boolean = false,
    )

    private data class RoutingSubmission(
        val id: String,
        val emailId: String,
        val recipient: String,
    )

    private class RecordingWorkflow(
        private val evidence: StalwartRoutingVerifierEvidence?,
        private val failure: Throwable? = null,
    ) : StalwartRoutingProofWorkflow {
        var request: StalwartRoutingProofRequest? = null
        var closed = false

        override suspend fun prove(
            request: StalwartRoutingProofRequest,
        ): StalwartRoutingVerifierEvidence {
            this.request = request
            failure?.let { throw it }
            return requireNotNull(evidence)
        }

        override fun close() {
            closed = true
        }
    }

    private class RecordingMailRemote(
        private val invocationId: String,
        private val failAt: String? = null,
    ) : StalwartRoutingMailRemote {
        val calls = mutableListOf<String>()
        val passwordArguments = mutableListOf<CharArray>()

        override suspend fun enroll(
            role: StalwartRoutingActorRole,
            actor: StalwartRoutingInputActor,
            normalPassword: CharArray,
        ): String {
            call("enroll:${role.value}")
            passwordArguments += normalPassword
            return "${role.value}apppassword"
        }

        override suspend fun submit(
            probe: StalwartRoutingProbeSpec,
            messageId: String,
        ): JsonObject {
            call("submit:${probe.name}")
            return if (probe.name == "registered_local") {
                buildJsonObject {
                    put("delivery_status", "unknown")
                    put("enhanced_status", "2.1.5")
                    put("queue_accepted", true)
                    put("recipient", probe.recipient)
                    put("smtp_code", 250)
                    put("submission_created", true)
                    put("submission_id", "registeredsubmission")
                    put("undo_status", "final")
                }
            } else {
                buildJsonObject {
                    put("delivery_status", "no")
                    put("enhanced_status", probe.enhancedStatus)
                    put("queue_accepted", false)
                    put("recipient", probe.recipient)
                    put("smtp_code", 550)
                    put("submission_created", true)
                    put(
                        "submission_id",
                        probe.name.replace("_", "") + "submission",
                    )
                    put("undo_status", "pending")
                }
            }
        }

        override suspend fun awaitRegisteredArrival(
            recipientAccountId: String,
            messageId: String,
        ): List<String> {
            call("arrival")
            assertEquals(
                "<mail-sandbox-routing-$invocationId@local.test>",
                messageId,
            )
            return listOf("recipientemail")
        }

        override suspend fun cleanupMailArtifacts() {
            call("cleanup-mail")
        }

        override suspend fun revoke(
            role: StalwartRoutingActorRole,
            credentialId: String,
        ) {
            call("revoke:${role.value}")
        }

        override suspend fun appPasswordInventory(
            role: StalwartRoutingActorRole,
        ): Set<String> {
            call("inventory:${role.value}")
            return emptySet()
        }

        override suspend fun revokedAuthenticationStatus(
            role: StalwartRoutingActorRole,
        ): Int {
            call("authenticate-revoked:${role.value}")
            return 401
        }

        override suspend fun readinessPreflight(
            role: StalwartRoutingActorRole,
        ): StalwartRoutingReadinessEvidence {
            call("readiness-preflight:${role.value}")
            return StalwartRoutingReadinessEvidence(
                projectedState =
                    StalwartMailAccessState.EnrollmentRequired,
                submissionCalls = 0,
                uploadCalls = 0,
            )
        }

        override suspend fun cleanup() {
            call("cleanup")
        }

        override fun close() = Unit

        private fun call(value: String) {
            calls += value
            if (value == failAt) {
                throw IllegalStateException("injected routing failure")
            }
        }
    }

    private companion object {
        const val SECRET_CANARY = "routing-password-canary-never-serialize"
        const val SENDER_PASSWORD = "sender-normal-password-test-only"
        const val RECIPIENT_PASSWORD = "recipient-normal-password-test-only"
        const val MANAGEMENT_API_KEY =
            "API_MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"
    }
}
