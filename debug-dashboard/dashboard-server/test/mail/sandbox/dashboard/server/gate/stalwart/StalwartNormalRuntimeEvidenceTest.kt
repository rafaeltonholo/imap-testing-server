package mail.sandbox.dashboard.server.gate.stalwart

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.ArrayDeque
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class StalwartNormalRuntimeEvidenceTest {
    @Test
    fun normalRuntimeSelectionAllowsOnlyTheTwoRequiredVariables() {
        val selected = StalwartNormalRuntimeEnvironment.load(
            mapOf(
                "STALWART_LIVE_TESTS" to "1",
                "STALWART_BASE_URL" to "http://127.0.0.1:8443",
            ),
        )

        assertEquals(URI("http://127.0.0.1:8443"), selected.baseUrl)
        val extras = listOf(
            "STALWART_GATE_FIXTURE_SECRETS_FILE",
            "STALWART_GATE_CREDENTIAL_ROOT",
            "STALWART_GATE_RESTART_PHASE",
            "STALWART_GATE_PREPARE",
            "STALWART_GATE_CLEANUP",
            "STALWART_GATE_PHASE",
        )
        extras.forEach { name ->
            assertFailsWith<IllegalArgumentException> {
                StalwartNormalRuntimeEnvironment.load(
                    mapOf(
                        "STALWART_LIVE_TESTS" to "1",
                        "STALWART_BASE_URL" to "http://127.0.0.1:8443",
                        name to "unit-value",
                    ),
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            StalwartNormalRuntimeEnvironment.load(
                mapOf(
                    "STALWART_LIVE_TESTS" to "1",
                    "STALWART_BASE_URL" to "http://127.0.0.1:8443",
                    "STALWART_UNREVIEWED_MATERIAL" to "unit-value",
                ),
            )
        }
    }

    @Test
    fun commandUsesExactArgvPrimaryRootAndSanitizedEnvironment() {
        withPrimaryRepository { root ->
            val launcher = FakeLauncher(
                FakeProcess(stdout = ByteArray(0)),
            )
            val consumer = StalwartNormalRuntimeEvidenceConsumer(
                launcher = launcher,
                pythonExecutableResolver = { Path.of("/usr/bin/python3") },
            )

            assertFailsWith<IllegalArgumentException> {
                consumer.load(root)
            }

            val request = launcher.requests.single()
            assertEquals(
                listOf(
                    "/usr/bin/python3",
                    root.resolve("scripts/stalwart_v016.py").toString(),
                    "normal-runtime-evidence",
                ),
                request.argv,
            )
            assertEquals(root, request.workingDirectory)
            assertEquals(
                mapOf(
                    "LANG" to "C",
                    "LC_ALL" to "C",
                    "PATH" to
                        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                    "PYTHONDONTWRITEBYTECODE" to "1",
                    "PYTHONHASHSEED" to "0",
                    "PYTHONNOUSERSITE" to "1",
                ),
                request.environment,
            )
            assertTrue(request.environment.keys.none { it.startsWith("STALWART_") })
            assertEquals(300_000, launcher.process.waitTimeouts.first())
        }
    }

    @Test
    fun commandTimeoutBoundsCoverTheAuthoritativeInternalValidation() {
        listOf(120_000L, 299_999L, 600_001L).forEach { timeout ->
            assertFailsWith<IllegalArgumentException> {
                StalwartNormalRuntimeEvidenceConsumer(
                    launcher = FakeLauncher(FakeProcess(ByteArray(0))),
                    pythonExecutableResolver = { Path.of("/usr/bin/python3") },
                    commandTimeoutMillis = timeout,
                )
            }
        }
    }

    @Test
    fun processTimeoutDestroysThenForciblyDestroysAndWaits() {
        withPrimaryRepository { root ->
            val process = FakeProcess(
                stdout = ByteArray(0),
                waitResults = listOf(false, false, true),
            )
            val consumer = StalwartNormalRuntimeEvidenceConsumer(
                launcher = FakeLauncher(process),
                pythonExecutableResolver = { Path.of("/usr/bin/python3") },
                commandTimeoutMillis = 300_000,
                terminationTimeoutMillis = 1,
            )

            assertFailsWith<IllegalArgumentException> {
                consumer.load(root)
            }

            assertTrue(process.destroyed)
            assertTrue(process.forciblyDestroyed)
            assertEquals(4, process.waitCalls)
            assertTrue(process.descendantTerminationCalls.contains(false))
            assertTrue(process.descendantTerminationCalls.contains(true))
            assertEquals(
                listOf("snapshot:false", "parent:false", "children:false"),
                process.terminationEvents.take(3),
            )
        }
    }

    @Test
    fun drainTimeoutAfterParentExitStillForciblyCleansTheProcessTree() {
        withPrimaryRepository { root ->
            val process = FakeProcess(
                stdout = ByteArray(0),
                stdoutStream = CloseBlockedInputStream(),
                waitResults = listOf(true, true),
            )

            assertFailsWith<IllegalArgumentException> {
                consumer(process).load(root)
            }

            assertTrue(process.forciblyDestroyed)
            assertEquals(listOf(true), process.descendantTerminationCalls)
        }
    }

    @Test
    fun interruptedDrainAfterParentExitCleansTreeAndPreservesInterrupt() {
        withPrimaryRepository { root ->
            val process = FakeProcess(
                stdout = ByteArray(0),
                stdoutStream = CloseBlockedInputStream(),
                waitResults = listOf(true, true),
            )

            try {
                Thread.currentThread().interrupt()
                assertFailsWith<InterruptedException> {
                    consumer(process).load(root)
                }

                assertTrue(Thread.currentThread().isInterrupted)
                assertTrue(process.forciblyDestroyed)
                assertEquals(listOf(true), process.descendantTerminationCalls)
            } finally {
                Thread.interrupted()
            }
        }
    }

    @Test
    fun parentExitCannotLeaveADescendantHoldingCommandPipesAlive() {
        val script = """
            sleep 60 &
            printf '%s\n' "${'$'}!" > descendant.pid
            sleep 1
        """.trimIndent()
        withPrimaryRepository(script = script) { root ->
            var descendant: ProcessHandle? = null
            try {
                assertFailsWith<IllegalArgumentException> {
                    StalwartNormalRuntimeEvidenceConsumer(
                        pythonExecutableResolver = { Path.of("/bin/sh") },
                        commandTimeoutMillis = 300_000,
                        terminationTimeoutMillis = 100,
                    ).load(root)
                }

                assertTrue(Files.exists(root.resolve("descendant.pid")))
                val pid = Files.readString(root.resolve("descendant.pid"))
                    .trim()
                    .toLong()
                descendant = ProcessHandle.of(pid).orElse(null)
                assertFalse(descendant?.isAlive ?: false)
            } finally {
                descendant?.takeIf(ProcessHandle::isAlive)?.let { handle ->
                    handle.destroyForcibly()
                    runCatching {
                        handle.onExit().get(2, TimeUnit.SECONDS)
                    }
                }
            }
        }
    }

    @Test
    fun unexpectedProcessFailureDoesNotDiscloseItsExceptionMessage() {
        withPrimaryRepository { root ->
            val marker = "unit-secret-unexpected-process-failure"
            val process = FakeProcess(
                stdout = ByteArray(0),
                exitFailure = IllegalStateException(marker),
            )

            val failure = assertFailsWith<IllegalArgumentException> {
                consumer(process).load(root)
            }

            assertEquals(
                "Normal-runtime evidence command failed safely",
                failure.message,
            )
            assertFalse(marker in failure.toString())
            assertFalse("IllegalStateException" in failure.toString())
        }
    }

    @Test
    fun nonzeroOversizedAndMalformedOutputFailWithoutDiagnosticsDisclosure() {
        withPrimaryRepository { root ->
            val marker = "unit-secret-child-diagnostic"
            val cases = listOf(
                FakeProcess(
                    stdout = ByteArray(0),
                    stderr = marker.encodeToByteArray(),
                    exitCode = 7,
                ),
                FakeProcess(
                    stdout = ByteArray(0),
                    stderr = marker.encodeToByteArray(),
                    exitCode = 0,
                ),
                FakeProcess(
                    stdout = ByteArray(
                        StalwartNormalRuntimeEvidenceConsumer.MAXIMUM_STDOUT_BYTES + 1,
                    ),
                ),
                FakeProcess(stdout = byteArrayOf(0xc3.toByte(), 0x28)),
                FakeProcess(stdout = "{}\n{}\n".encodeToByteArray()),
                FakeProcess(stdout = "{ \"payload\":{}}\n".encodeToByteArray()),
            )

            cases.forEach { process ->
                val failure = assertFailsWith<IllegalArgumentException> {
                    StalwartNormalRuntimeEvidenceConsumer(
                        launcher = FakeLauncher(process),
                        pythonExecutableResolver = { Path.of("/usr/bin/python3") },
                    ).load(root)
                }
                assertFalse(marker in failure.toString())
            }
        }
    }

    @Test
    fun drainFailureInterruptAndFailedFinalWaitCleanUpSafely() {
        withPrimaryRepository { root ->
            val drainFailure = FakeProcess(
                stdout = ByteArray(0),
                stdoutStream = object : InputStream() {
                    override fun read(): Int =
                        throw IOException("unit-secret-drain-failure")
                },
            )
            assertFailsWith<IllegalArgumentException> {
                consumer(drainFailure).load(root)
            }

            val interrupted = FakeProcess(
                stdout = ByteArray(0),
                waitFailure = InterruptedException(),
                waitResults = listOf(true),
            )
            try {
                assertFailsWith<InterruptedException> {
                    consumer(interrupted).load(root)
                }
                assertTrue(Thread.currentThread().isInterrupted)
                assertTrue(interrupted.forciblyDestroyed)
            } finally {
                Thread.interrupted()
            }

            val interruptedDuringTreeTermination = FakeProcess(
                stdout = ByteArray(0),
                waitResults = listOf(false, true),
                treeFailure = InterruptedException(),
            )
            try {
                assertFailsWith<InterruptedException> {
                    consumer(interruptedDuringTreeTermination).load(root)
                }
                assertTrue(Thread.currentThread().isInterrupted)
                assertEquals(
                    listOf(false, true),
                    interruptedDuringTreeTermination
                        .descendantTerminationCalls,
                )
                assertEquals(
                    listOf(
                        "snapshot:false",
                        "parent:false",
                        "snapshot:true",
                        "parent:true",
                        "children:true",
                    ),
                    interruptedDuringTreeTermination.terminationEvents,
                )
                assertTrue(interruptedDuringTreeTermination.forciblyDestroyed)
            } finally {
                Thread.interrupted()
            }

            val interruptedDuringCleanup = FakeProcess(
                stdout = ByteArray(0),
                waitResults = listOf(false, true),
                waitFailure = InterruptedException(),
                waitFailureCall = 2,
            )
            try {
                assertFailsWith<InterruptedException> {
                    consumer(interruptedDuringCleanup).load(root)
                }
                assertTrue(Thread.currentThread().isInterrupted)
                assertTrue(interruptedDuringCleanup.destroyed)
                assertTrue(
                    interruptedDuringCleanup.descendantTerminationCalls.size >= 2,
                )
            } finally {
                Thread.interrupted()
            }

            val failedFinalWait = FakeProcess(
                stdout = ByteArray(0),
                waitResults = listOf(false, false, false),
            )
            assertFailsWith<IllegalArgumentException> {
                consumer(failedFinalWait).load(root)
            }
            assertTrue(failedFinalWait.destroyed)
            assertTrue(failedFinalWait.forciblyDestroyed)
            assertEquals(4, failedFinalWait.waitCalls)
        }
    }

    @Test
    fun digestEnvelopeRejectsMismatchExtraPartialAndMultipleLines() {
        val payload =
            """{"schema":"unit.digest-envelope"}"""
        val digest = sha256(payload.encodeToByteArray())
        val valid =
            """{"payload":$payload,"payload_sha256":"$digest"}""" + "\n"

        assertEquals(
            payload,
            StalwartNormalRuntimeEvidence.decodeDigestEnvelope(
                valid.encodeToByteArray(),
                "normal-runtime evidence",
            ).toString(),
        )
        listOf(
            valid.dropLast(1),
            valid + valid,
            valid.replace(digest, "0".repeat(64)),
            """{"payload":$payload,"payload_sha256":"$digest","extra":true}""" + "\n",
            """{ "payload":$payload,"payload_sha256":"$digest"}""" + "\n",
        ).forEach { invalid ->
            assertFailsWith<IllegalArgumentException> {
                StalwartNormalRuntimeEvidence.decodeDigestEnvelope(
                    invalid.encodeToByteArray(),
                    "normal-runtime evidence",
                )
            }
        }
    }

    @Test
    fun decoderPreservesAccountAndCredentialArrayOrderAndMultiplicity() {
        val decoded = StalwartNormalRuntimeEvidence.decode(validEnvelope())

        assertEquals("management-id", decoded.management.accountId)
        assertEquals("api-key-id", decoded.management.apiKeyId)
        assertEquals(listOf("management-id"), decoded.protectedAccountIds)
        assertEquals(401, decoded.oldRecoveryAuthenticationStatus)
        assertEquals(
            listOf("shared" to "local.test", "shared" to "other.test"),
            decoded.migratedAccounts.map { it.identity },
        )
        assertEquals(
            listOf("create-0", "create-1"),
            decoded.migratedAccounts.first()
                .domainReferences.map { it.clientId },
        )
        assertEquals(
            listOf("0"),
            decoded.migratedAccounts.first()
                .credentialProjections.map { it.slot },
        )
        assertEquals(
            listOf("Password"),
            decoded.migratedAccounts.first().credentialProjections.map {
                it.projection.getValue("@type").jsonPrimitive.content
            },
        )
        val empty = JsonObject(
            validPayload() + ("migrated_accounts" to JsonArray(emptyList())),
        )
        assertTrue(
            StalwartNormalRuntimeEvidence.decode(envelope(empty))
                .migratedAccounts.isEmpty(),
        )
    }

    @Test
    fun decoderRejectsSchemaShapeNativeTypeAndUnsafeSecretMutations() {
        val payload = validPayload()
        val malformed = listOf(
            JsonObject(payload - "protected_account_ids"),
            JsonObject(payload + ("extra" to JsonPrimitive(true))),
            JsonObject(
                payload + (
                    "old_recovery_auth_status" to JsonPrimitive("401")
                    ),
            ),
            JsonObject(
                payload + (
                    "management" to JsonObject(
                        payload.getValue("management").jsonObject +
                            ("extra" to JsonPrimitive(true)),
                    )
                    ),
            ),
            mutateManagement(payload) { management ->
                val wrapper = management.getValue("account_projection").jsonObject
                JsonObject(
                    management + (
                        "account_projection" to JsonObject(
                            wrapper + ("extra" to JsonPrimitive(true)),
                        )
                        ),
                )
            },
            mutateManagement(payload) { management ->
                val inventory =
                    management.getValue("credential_inventory") as JsonArray
                JsonObject(
                    management + (
                        "credential_inventory" to JsonArray(
                            listOf(
                                JsonObject(
                                    inventory.single().jsonObject - "permissions",
                                ),
                            ),
                        )
                        ),
                )
            },
            mutateManagement(payload) { management ->
                val wrapper = management.getValue("api_key_projection").jsonObject
                val value = wrapper.getValue("value").jsonObject
                JsonObject(
                    management + (
                        "api_key_projection" to JsonObject(
                            wrapper + (
                                "value" to JsonObject(
                                    value + ("extra" to JsonPrimitive(true)),
                                )
                                ),
                        )
                        ),
                )
            },
            withUnsafeCredentialSecret(payload),
        )

        malformed.forEach {
            assertFailsWith<IllegalArgumentException> {
                StalwartNormalRuntimeEvidence.decode(envelope(it))
            }
        }
    }

    @Test
    fun decoderRejectsMalformedMissingDuplicateUnusedAndForbiddenDomainReferences() {
        val payload = validPayload()
        val migrated = payload.getValue("migrated_accounts") as JsonArray
        val first = migrated.first().jsonObject
        val references = first.getValue("domain_references") as JsonArray
        val malformedAccounts = listOf(
            JsonObject(first + ("domain_references" to JsonArray(references.dropLast(1)))),
            JsonObject(first + ("domain_references" to JsonArray(references + references.first()))),
            JsonObject(
                first + (
                    "domain_references" to JsonArray(
                        references + jsonObject(
                            """{"client_id":"create-9","domain_name":"unused.test"}""",
                        ),
                    )
                    ),
            ),
            JsonObject(first + ("domain_references" to JsonArray(references.reversed()))),
            JsonObject(
                first + (
                    "domain_references" to JsonArray(
                        listOf(
                            JsonObject(
                                references.first().jsonObject +
                                    ("client_id" to JsonPrimitive("domain-one")),
                            ),
                            references[1],
                        ),
                    )
                    ),
            ),
            JsonObject(
                first + (
                    "domain_references" to JsonArray(
                        listOf(
                            references.first(),
                            jsonObject(
                                """{"client_id":"create-0","domain_name":"other.test"}""",
                            ),
                        ),
                    )
                    ),
            ),
            JsonObject(
                first + (
                    "account_projection" to JsonObject(
                        first.getValue("account_projection").jsonObject +
                            ("tenantId" to JsonPrimitive("#create-0")),
                    )
                    ),
            ),
            JsonObject(
                first + (
                    "account_projection" to JsonObject(
                        first.getValue("account_projection").jsonObject +
                            (
                                "aliases" to JsonObject(
                                    mapOf(
                                        "1" to first.getValue("account_projection")
                                            .jsonObject.getValue("aliases")
                                            .jsonObject.getValue("0"),
                                    ),
                                )
                                ),
                    )
                    ),
            ),
            JsonObject(
                first + (
                    "account_projection" to JsonObject(
                        first.getValue("account_projection").jsonObject +
                            ("memberTenantId" to JsonPrimitive("tenant-one")),
                    )
                    ),
            ),
            JsonObject(
                first + (
                    "account_projection" to JsonObject(
                        first.getValue("account_projection").jsonObject +
                            (
                                "quotas" to jsonObject(
                                    """{"maxDiskQuota":0}""",
                                )
                                ),
                    )
                    ),
            ),
            JsonObject(
                first + (
                    "account_projection" to JsonObject(
                        first.getValue("account_projection").jsonObject +
                            ("#forbidden" to JsonPrimitive("value")),
                    )
                    ),
            ),
            JsonObject(
                first + (
                    "account_projection" to JsonObject(
                        first.getValue("account_projection").jsonObject +
                            ("domainId" to JsonPrimitive("create-0")),
                    )
                    ),
            ),
            JsonObject(
                first + (
                    "domain_references" to JsonArray(
                        listOf(
                            JsonObject(
                                references.first().jsonObject +
                                    ("extra" to JsonPrimitive(true)),
                            ),
                            references[1],
                        ),
                    )
                    ),
            ),
        )
        malformedAccounts.forEach { changed ->
            assertFailsWith<IllegalArgumentException> {
                StalwartNormalRuntimeEvidence.decode(
                    envelope(
                        JsonObject(
                            payload + (
                                "migrated_accounts" to JsonArray(
                                    listOf(changed) + migrated.drop(1),
                                )
                                ),
                        ),
                    ),
                )
            }
        }
    }

    @Test
    fun decoderRejectsCredentialSlotTypeShapeAndCaseInsensitiveSensitiveKeys() {
        val payload = validPayload()
        val migrated = payload.getValue("migrated_accounts") as JsonArray
        val first = migrated.first().jsonObject
        val credentials = first.getValue("credential_projections") as JsonArray
        val firstCredential = credentials.first().jsonObject
        val projection = firstCredential.getValue("projection").jsonObject
        val malformedCredentials = listOf(
            JsonObject(firstCredential + ("slot" to JsonPrimitive("01"))),
            JsonObject(firstCredential + ("slot" to JsonPrimitive("1"))),
            JsonObject(
                firstCredential + (
                    "projection" to JsonObject(
                        projection + ("@type" to JsonPrimitive("AppPassword")),
                    )
                    ),
            ),
            JsonObject(firstCredential + ("extra" to JsonPrimitive(true))),
            JsonObject(
                firstCredential + (
                    "projection" to JsonObject(
                        projection + ("Secret" to JsonPrimitive("****")),
                    )
                    ),
            ),
            JsonObject(
                firstCredential + (
                    "projection" to JsonObject(
                        projection + ("ToKeN" to JsonPrimitive("****")),
                    )
                    ),
            ),
            JsonObject(
                firstCredential + (
                    "projection" to JsonObject(
                        projection + ("algorithm" to JsonPrimitive("argon2id")),
                    )
                    ),
            ),
        )
        val malformedAccounts = malformedCredentials.map { changed ->
            JsonObject(
                first + (
                    "credential_projections" to JsonArray(
                        listOf(changed) + credentials.drop(1),
                    )
                    ),
            )
        } + JsonObject(
            first + (
                "credential_projections" to JsonArray(
                    listOf(credentials.first(), credentials.first()),
                )
                ),
        ) + JsonObject(
            first + (
                "account_projection" to JsonObject(
                    first.getValue("account_projection").jsonObject +
                        ("ToKeN" to JsonPrimitive("****")),
                )
                ),
        )
        malformedAccounts.forEach { changed ->
            assertFailsWith<IllegalArgumentException> {
                StalwartNormalRuntimeEvidence.decode(
                    envelope(
                        JsonObject(
                            payload + (
                                "migrated_accounts" to JsonArray(
                                    listOf(changed) + migrated.drop(1),
                                )
                                ),
                        ),
                    ),
                )
            }
        }
    }

    @Test
    fun decoderRejectsConflictingDomainBindingsAcrossAccounts() {
        val payload = validPayload()
        val migrated = payload.getValue("migrated_accounts") as JsonArray
        val second = migrated[1].jsonObject
        val secondReferences = second.getValue("domain_references") as JsonArray
        val secondReference = secondReferences.single().jsonObject
        val conflictingClient = JsonObject(
            second + (
                "domain_references" to JsonArray(
                    listOf(
                        JsonObject(
                            secondReference +
                                ("domain_name" to JsonPrimitive("local.test")),
                        ),
                    ),
                )
                ),
        )
        val renamedProjection = JsonObject(
            second.getValue("account_projection").jsonObject +
                ("domainId" to JsonPrimitive("#create-2")),
        )
        val conflictingName = JsonObject(
            second + mapOf(
                "account_projection" to renamedProjection,
                "domain_references" to JsonArray(
                    listOf(
                        jsonObject(
                            """{"client_id":"create-2","domain_name":"other.test"}""",
                        ),
                    ),
                ),
            ),
        )

        listOf(conflictingClient, conflictingName).forEach { changed ->
            assertFailsWith<IllegalArgumentException> {
                StalwartNormalRuntimeEvidence.decode(
                    envelope(
                        JsonObject(
                            payload + (
                                "migrated_accounts" to JsonArray(
                                    listOf(migrated.first(), changed),
                                )
                                ),
                        ),
                    ),
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            StalwartNormalRuntimeEvidence.decode(
                envelope(
                    JsonObject(
                        payload + (
                            "migrated_accounts" to JsonArray(
                                listOf(migrated.first(), migrated.first()),
                            )
                            ),
                    ),
                ),
            )
        }
    }

    @Test
    fun domainReferencesResolveOnlyAgainstUniqueLiveDomainNames() {
        val expected = StalwartNormalRuntimeEvidence.decode(validEnvelope())
            .migratedAccounts.first()
        val resolved = resolveMigratedAccountProjection(
            expected,
            mapOf(
                "live-local-id" to "local.test",
                "live-other-id" to "other.test",
            ),
        )

        assertEquals(
            "live-local-id",
            resolved.getValue("domainId").jsonPrimitive.content,
        )
        assertEquals(
            "live-other-id",
            resolved.getValue("aliases").jsonObject
                .getValue("0").jsonObject
                .getValue("domainId").jsonPrimitive.content,
        )
        assertFailsWith<IllegalArgumentException> {
            resolveMigratedAccountProjection(
                expected,
                mapOf(
                    "duplicate-one" to "local.test",
                    "duplicate-two" to "local.test",
                    "live-other-id" to "other.test",
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            resolveMigratedAccountProjection(
                expected,
                mapOf("live-local-id" to "local.test"),
            )
        }
    }

    @Test
    fun migratedCredentialComparatorIsExactBySlotAndSecretSafe() {
        val expected = listOf(
            StalwartMigratedCredentialProjection(
                slot = "0",
                projection = jsonObject(
                    """
                        {
                          "@type":"Password",
                          "secret":"****"
                        }
                    """.trimIndent(),
                ),
            ),
        )
        val actual = listOf(
            "0" to jsonObject(
                """
                    {
                      "@type":"Password",
                      "allowedIps":{},
                      "credentialId":"generated-one",
                      "secret":"********"
                    }
                """.trimIndent(),
            ),
        )

        assertMigratedCredentialProjections(expected, actual)

        val marker = "unit-secret-actual-value"
        val invalid = listOf(
            emptyList(),
            listOf(
                actual[0],
                "1" to actual[0].second,
            ),
            listOf(
                actual[0].first to JsonObject(
                    actual[0].second + ("extra" to JsonPrimitive(true)),
                ),
            ),
            listOf(
                actual[0].first to JsonObject(
                    actual[0].second +
                        ("secret" to JsonPrimitive("changed-property")),
                ),
            ),
            listOf(
                actual[0].first to JsonObject(
                    actual[0].second + ("secret" to JsonPrimitive(marker)),
                ),
            ),
        )
        invalid.forEach { changed ->
            val failure = assertFailsWith<IllegalArgumentException> {
                assertMigratedCredentialProjections(expected, changed)
            }
            assertFalse(marker in failure.toString())
        }
    }

    @Test
    fun repositoryScriptsAncestorMustNotBeASymbolicLink() {
        withPrimaryRepository { root ->
            val external = Files.createTempDirectory("stalwart-normal-external")
            try {
                Files.writeString(
                    external.resolve("stalwart_v016.py"),
                    "# unit fixture\n",
                )
                root.resolve("scripts").toFile().deleteRecursively()
                Files.createSymbolicLink(root.resolve("scripts"), external)

                assertFailsWith<IllegalArgumentException> {
                    StalwartNormalRuntimeEvidenceConsumer(
                        launcher = FakeLauncher(FakeProcess(ByteArray(0))),
                        pythonExecutableResolver = { Path.of("/usr/bin/python3") },
                    ).load(root)
                }
            } finally {
                external.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun registryObjectsAreFetchedInExactBoundedChunks() = runBlocking {
        val ids = (0 until 205).map { "account-$it" }
        val initialQuery = GateRegistryQuerySnapshot(
            ids = ids,
            queryState = "account-query-state",
        )
        val chunks = mutableListOf<List<String>>()
        var requeryCount = 0
        val objects = registryObjectsInChunks(
            querySnapshot = initialQuery,
            objectType = "Account",
            accountId = "management-id",
            fetch = { chunk ->
                chunks += chunk
                registryGetResponse(chunk, state = "account-get-state")
            },
            requery = {
                requeryCount += 1
                initialQuery.copy(ids = initialQuery.ids.toList())
            },
        )

        assertEquals(listOf(100, 100, 5), chunks.map { it.size })
        assertEquals(ids.toSet(), objects.keys)
        assertEquals(1, requeryCount)
        assertFailsWith<IllegalArgumentException> {
            registryObjectsInChunks(
                querySnapshot = initialQuery.copy(ids = ids.take(2)),
                objectType = "Account",
                accountId = "management-id",
                fetch = { chunk ->
                    registryGetResponse(chunk.dropLast(1))
                },
                requery = { initialQuery.copy(ids = ids.take(2)) },
            )
        }
        assertFailsWith<IllegalArgumentException> {
            registryObjectsInChunks(
                querySnapshot = GateRegistryQuerySnapshot(
                    ids = listOf("duplicate", "duplicate"),
                    queryState = "query-state",
                ),
                objectType = "Account",
                accountId = "management-id",
                fetch = ::registryGetResponse,
                requery = {
                    GateRegistryQuerySnapshot(
                        ids = listOf("duplicate", "duplicate"),
                        queryState = "query-state",
                    )
                },
            )
        }
        assertFailsWith<IllegalArgumentException> {
            registryObjectsInChunks(
                querySnapshot = GateRegistryQuerySnapshot(
                    ids = listOf("account-one"),
                    queryState = "query-state",
                ),
                objectType = "Account",
                accountId = "management-id",
                fetch = { chunk ->
                    registryGetResponse(chunk, includeNotFound = false)
                },
                requery = {
                    GateRegistryQuerySnapshot(
                        ids = listOf("account-one"),
                        queryState = "query-state",
                    )
                },
            )
        }
        Unit
    }

    @Test
    fun registryObjectChunksRejectChangedGetAndPostQuerySnapshots() =
        runBlocking {
            val ids = (0 until 101).map { "account-$it" }
            val initialQuery = GateRegistryQuerySnapshot(
                ids = ids,
                queryState = "query-state",
            )
            var getCount = 0
            assertFailsWith<IllegalArgumentException> {
                registryObjectsInChunks(
                    querySnapshot = initialQuery,
                    objectType = "Account",
                    accountId = "management-id",
                    fetch = { chunk ->
                        getCount += 1
                        registryGetResponse(
                            ids = chunk,
                            state = "get-state-$getCount",
                        )
                    },
                    requery = { initialQuery },
                )
            }

            listOf(
                initialQuery.copy(queryState = "changed-query-state"),
                initialQuery.copy(ids = initialQuery.ids.reversed()),
            ).forEach { changed ->
                assertFailsWith<IllegalArgumentException> {
                    registryObjectsInChunks(
                        querySnapshot = initialQuery,
                        objectType = "Account",
                        accountId = "management-id",
                        fetch = { chunk ->
                            registryGetResponse(
                                ids = chunk,
                                state = "stable-get-state",
                            )
                        },
                        requery = { changed },
                    )
                }
            }
        }

    @Test
    fun registryGetRejectsUnsafeNotFoundIdsBeforeTheEmptyCheck() {
        val marker = "server-controlled/not-found-marker"
        val failure = assertFailsWith<IllegalArgumentException> {
            registryObjects(
                response = registryGetResponse(
                    ids = emptyList(),
                    notFound = JsonArray(listOf(JsonPrimitive(marker))),
                ),
                expectedMethod = "x:Account/get",
                accountId = "management-id",
            )
        }

        assertEquals(
            "Registry get returned an invalid notFound object ID",
            failure.message,
        )
        assertFalse(marker in failure.toString())
    }

    @Test
    fun registryGetAcceptsBoundedOpaqueStateTokens() {
        assertEquals(
            emptyMap(),
            registryObjects(
                response = registryGetResponse(
                    ids = emptyList(),
                    state = " ",
                ),
                expectedMethod = "x:Account/get",
                accountId = "management-id",
            ),
        )
    }

    @Test
    fun registryGetRejectsUnsafeIdsOpaqueTokensAndUnexpectedServerValues() {
        val marker = "server-controlled/get-marker"
        val invalid = listOf(
            registryGetResponse(
                ids = listOf("safe-id"),
                returnedIds = listOf(JsonPrimitive("$marker/unsafe")),
            ),
            registryGetResponse(
                ids = listOf("safe-id"),
                returnedIds = listOf(JsonPrimitive("x".repeat(256))),
            ),
            registryGetResponse(ids = emptyList(), state = ""),
            registryGetResponse(
                ids = emptyList(),
                state = "x".repeat(4_097),
            ),
            registryGetResponse(
                ids = emptyList(),
                state = "\uD800",
            ),
            registryGetResponse(
                ids = emptyList(),
                callId = JsonPrimitive("x".repeat(4_097)),
            ),
            registryGetResponse(
                ids = emptyList(),
                accountId = JsonPrimitive(marker),
            ),
            registryGetResponse(
                ids = emptyList(),
                method = JsonPrimitive(marker),
            ),
            registryGetResponse(ids = emptyList()) {
                this[marker] = JsonPrimitive(marker)
            },
        )

        invalid.forEach { response ->
            val failure = assertFails {
                registryObjects(
                    response = response,
                    expectedMethod = "x:Account/get",
                    accountId = "management-id",
                )
            }
            assertFalse(marker in failure.toString())
        }
    }

    private fun withPrimaryRepository(
        script: String = "# unit fixture\n",
        block: (Path) -> Unit,
    ) {
        val root = Files.createTempDirectory("stalwart-normal-evidence")
            .toRealPath()
        try {
            Files.createDirectory(root.resolve(".git"))
            Files.createDirectories(root.resolve("scripts"))
            Files.writeString(
                root.resolve("scripts/stalwart_v016.py"),
                script,
            )
            Files.createDirectories(root.resolve("debug-dashboard"))
            Files.writeString(
                root.resolve("debug-dashboard/project.yaml"),
                "modules: []\n",
            )
            block(root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun validEnvelope(): ByteArray = envelope(validPayload())

    private fun withUnsafeCredentialSecret(payload: JsonObject): JsonObject {
        val accounts = payload.getValue("migrated_accounts") as JsonArray
        val first = accounts.first().jsonObject
        val credentials = first.getValue("credential_projections") as JsonArray
        val firstCredential = credentials.first().jsonObject
        val changedCredential = JsonObject(
            firstCredential + (
                "projection" to JsonObject(
                    firstCredential.getValue("projection").jsonObject +
                        ("secret" to JsonPrimitive("unit-secret")),
                )
                ),
        )
        val changedAccount = JsonObject(
            first + (
                "credential_projections" to JsonArray(
                    listOf(changedCredential) + credentials.drop(1),
                )
                ),
        )
        return JsonObject(
            payload + (
                "migrated_accounts" to JsonArray(
                    listOf(changedAccount) + accounts.drop(1),
                )
                ),
        )
    }

    private fun mutateManagement(
        payload: JsonObject,
        transform: (JsonObject) -> JsonObject,
    ): JsonObject =
        JsonObject(
            payload + (
                "management" to transform(
                    payload.getValue("management").jsonObject,
                )
                ),
        )

    private fun validPayload(): JsonObject =
        Json.parseToJsonElement(
            """
                {
                  "management":{
                    "account_id":"management-id",
                    "account_projection":{
                      "id":"management-id",
                      "object_type":"Account",
                      "value":{
                        "@type":"User",
                        "name":"dashboard-management",
                        "permissions":{},
                        "roles":{"@type":"User"}
                      }
                    },
                    "api_key_id":"api-key-id",
                    "api_key_projection":{
                      "id":"api-key-id",
                      "object_type":"ApiKey",
                      "value":{
                        "accountId":"management-id",
                        "allowedIps":{},
                        "credentialType":"ApiKey",
                        "description":"mail-sandbox/debug-dashboard/management",
                        "permissions":{}
                      }
                    },
                    "credential_inventory":[{
                      "account_id":"management-id",
                      "allowed_ips":{},
                      "credential_id":"api-key-id",
                      "credential_type":"ApiKey",
                      "description":"mail-sandbox/debug-dashboard/management",
                      "permissions":{}
                    }]
                  },
                  "migrated_accounts":[{
                    "account_projection":{
                      "@type":"User",
                      "aliases":{
                        "0":{
                          "domainId":"#create-1",
                          "name":"nested-alias"
                        }
                      },
                      "description":"first",
                      "domainId":"#create-0",
                      "memberGroupIds":{},
                      "name":"shared",
                      "quotas":{}
                    },
                    "credential_projections":[{
                      "projection":{"@type":"Password","secret":"****"},
                      "slot":"0"
                    }],
                    "domain_references":[{
                      "client_id":"create-0",
                      "domain_name":"local.test"
                    },{
                      "client_id":"create-1",
                      "domain_name":"other.test"
                    }]
                  },{
                    "account_projection":{
                      "@type":"User",
                      "aliases":{},
                      "domainId":"#create-1",
                      "memberGroupIds":{},
                      "name":"shared",
                      "quotas":{}
                    },
                    "credential_projections":[{
                      "projection":{"@type":"Password","secret":"****"},
                      "slot":"0"
                    }],
                    "domain_references":[{
                      "client_id":"create-1",
                      "domain_name":"other.test"
                    }]
                  }],
                  "old_recovery_auth_status":401,
                  "protected_account_ids":["management-id"],
                  "schema":"mail-sandbox.stalwart-v016-normal-runtime-evidence.v2"
                }
            """.trimIndent(),
        ).jsonObject

    private fun jsonObject(content: String): JsonObject =
        Json.parseToJsonElement(content).jsonObject

    private fun registryGetResponse(
        ids: List<String>,
        includeNotFound: Boolean = true,
        state: String = "unit-state",
        notFound: JsonElement = JsonArray(emptyList()),
        returnedIds: List<JsonElement> = ids.map(::JsonPrimitive),
        accountId: JsonElement = JsonPrimitive("management-id"),
        method: JsonElement = JsonPrimitive("x:Account/get"),
        callId: JsonElement = JsonPrimitive("unit-call"),
        mutatePayload: MutableMap<String, JsonElement>.() -> Unit = {},
    ): JsonObject {
        val payloadValues = mutableMapOf<String, JsonElement>(
            "accountId" to accountId,
            "list" to JsonArray(
                returnedIds.map { id ->
                    JsonObject(mapOf("id" to id))
                },
            ),
            "state" to JsonPrimitive(state),
        )
        if (includeNotFound) {
            payloadValues["notFound"] = notFound
        }
        payloadValues.mutatePayload()
        val payload = JsonObject(payloadValues)
        return JsonObject(
            mapOf(
                "methodResponses" to JsonArray(
                    listOf(
                        JsonArray(
                            listOf(
                                method,
                                payload,
                                callId,
                            ),
                        ),
                    ),
                ),
            ),
        )
    }

    private fun envelope(payload: JsonObject): ByteArray {
        val canonicalPayload = StalwartRoutingCanonicalJson.encode(payload)
        val envelope = Json.parseToJsonElement(
            """
                {
                  "payload":$canonicalPayload,
                  "payload_sha256":"${sha256(canonicalPayload.encodeToByteArray())}"
                }
            """.trimIndent(),
        )
        return (
            StalwartRoutingCanonicalJson.encode(envelope) + "\n"
            ).encodeToByteArray()
    }

    private fun consumer(
        process: FakeProcess,
    ): StalwartNormalRuntimeEvidenceConsumer =
        StalwartNormalRuntimeEvidenceConsumer(
            launcher = FakeLauncher(process),
            pythonExecutableResolver = { Path.of("/usr/bin/python3") },
            commandTimeoutMillis = 300_000,
            terminationTimeoutMillis = 1_000,
        )

    private class CloseBlockedInputStream : InputStream() {
        private val closed = CountDownLatch(1)

        override fun read(): Int =
            try {
                closed.await()
                -1
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                -1
            }

        override fun close() {
            closed.countDown()
        }
    }

    private class FakeLauncher(
        val process: FakeProcess,
    ) : StalwartEvidenceProcessLauncher {
        val requests = mutableListOf<StalwartEvidenceProcessRequest>()

        override fun start(
            request: StalwartEvidenceProcessRequest,
        ): StalwartEvidenceProcess {
            requests += request
            return process
        }
    }

    private class FakeProcess(
        stdout: ByteArray,
        stderr: ByteArray = ByteArray(0),
        stdoutStream: InputStream? = null,
        private val exitCode: Int = 0,
        private val exitFailure: RuntimeException? = null,
        waitResults: List<Boolean> = listOf(true),
        waitFailure: InterruptedException? = null,
        private val waitFailureCall: Int = 1,
        treeFailure: InterruptedException? = null,
        private val treeFailureCall: Int = 1,
    ) : StalwartEvidenceProcess {
        override val stdout: InputStream =
            stdoutStream ?: ByteArrayInputStream(stdout)
        override val stderr: InputStream = ByteArrayInputStream(stderr)
        private val waits = ArrayDeque(waitResults)
        private var waitFailure = waitFailure
        private var treeFailure = treeFailure
        private var treeCalls = 0
        private var descendantsObserved = false
        var destroyed = false
        var forciblyDestroyed = false
        var waitCalls = 0
        val waitTimeouts = mutableListOf<Long>()
        val descendantTerminationCalls = mutableListOf<Boolean>()
        val terminationEvents = mutableListOf<String>()

        override fun closeStdin() = Unit

        override fun waitFor(timeoutMillis: Long): Boolean {
            waitCalls += 1
            waitTimeouts += timeoutMillis
            waitFailure?.takeIf { waitCalls == waitFailureCall }?.let {
                waitFailure = null
                throw it
            }
            return if (waits.isEmpty()) true else waits.removeFirst()
        }

        override fun exitValue(): Int =
            exitFailure?.let { throw it } ?: exitCode

        override fun terminateTree(
            forcibly: Boolean,
            timeoutMillis: Long,
        ): Boolean {
            treeCalls += 1
            terminationEvents += "snapshot:$forcibly"
            if (treeCalls == 1) {
                descendantsObserved = true
            }
            terminationEvents += "parent:$forcibly"
            if (forcibly) {
                forciblyDestroyed = true
            } else {
                destroyed = true
            }
            descendantTerminationCalls += forcibly
            treeFailure?.takeIf { treeCalls == treeFailureCall }?.let {
                treeFailure = null
                throw it
            }
            check(descendantsObserved)
            terminationEvents += "children:$forcibly"
            return true
        }
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString(separator = "") { "%02x".format(it) }
}
