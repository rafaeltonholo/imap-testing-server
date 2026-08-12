package mail.sandbox.dashboard.server.acceptance

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.GenerateMessageResponse
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.server.api.DashboardApiError
import mail.sandbox.dashboard.server.local.LocalDashboardBackend
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationAttempt
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationConnector
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProbe
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProtocol
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationTransportOutcome

class SingleStackPreservationTest {
    @Test
    fun stalwartAcceptanceProfilesHaveStableProtocolsSlugsAndExactOwnedAddresses() {
        val run = AcceptanceRunIdentity("dashboard-acceptance-1786380000-a1b2c3d4")

        assertEquals(
            listOf(
                StalwartAcceptanceProfile.JMAP_ONLY,
                StalwartAcceptanceProfile.SMTP_ONLY,
                StalwartAcceptanceProfile.JMAP_SMTP,
            ),
            StalwartAcceptanceProfile.entries,
        )
        assertEquals("jmap-only", StalwartAcceptanceProfile.JMAP_ONLY.slug)
        assertEquals(listOf(MailProtocol.JMAP), StalwartAcceptanceProfile.JMAP_ONLY.protocols)
        assertEquals("smtp-only", StalwartAcceptanceProfile.SMTP_ONLY.slug)
        assertEquals(listOf(MailProtocol.SMTP), StalwartAcceptanceProfile.SMTP_ONLY.protocols)
        assertEquals("jmap-smtp", StalwartAcceptanceProfile.JMAP_SMTP.slug)
        assertEquals(
            listOf(MailProtocol.JMAP, MailProtocol.SMTP),
            StalwartAcceptanceProfile.JMAP_SMTP.protocols,
        )
        assertEquals(
            "${run.prefix}-dovecot@local.test",
            run.accountAddress(Provider.DOVECOT),
        )
        assertEquals(
            "${run.prefix}-stalwart-jmap-only@local.test",
            run.accountAddress(StalwartAcceptanceProfile.JMAP_ONLY),
        )
        assertEquals(
            "${run.prefix}-stalwart-smtp-only@local.test",
            run.accountAddress(StalwartAcceptanceProfile.SMTP_ONLY),
        )
        assertEquals(
            "${run.prefix}-stalwart-jmap-smtp@local.test",
            run.accountAddress(StalwartAcceptanceProfile.JMAP_SMTP),
        )

        val exactOwned = setOf(
            run.accountAddress(Provider.DOVECOT),
            *StalwartAcceptanceProfile.entries.map(run::accountAddress).toTypedArray(),
        )
        assertTrue(exactOwned.all(run::ownsAddress))
        assertFalse(run.ownsAddress("${run.prefix}-stalwart@local.test"))
        assertFalse(run.ownsAddress("${run.prefix}-stalwart-jmap-only-extra@local.test"))
    }

    @Test
    fun generatedStalwartCleanupRequiresTheExactReturnedProviderAccountId() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val returned = AccountInfo(
                address = environment.run.accountAddress(StalwartAcceptanceProfile.JMAP_ONLY),
                provider = Provider.STALWART,
                protocols = StalwartAcceptanceProfile.JMAP_ONLY.protocols,
                credentialReadiness = CredentialReadiness.READY,
                providerAccountId = "returned-account-id",
            )

            environment.requireGeneratedAccount(returned, "returned-account-id")
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAccount(returned, null)
            }
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAccount(returned, "different-account-id")
            }
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAccount(
                    returned.copy(address = "${environment.run.prefix}-stalwart@local.test"),
                    "returned-account-id",
                )
            }
        }
    }

    @Test
    fun uncertainCreateRecoverySelectsOnlyAnExactNonBaselineRunOwnedIdentity() {
        val run = AcceptanceRunIdentity("dashboard-acceptance-1786380000-a1b2c3d4")
        val address = run.accountAddress(StalwartAcceptanceProfile.JMAP_ONLY)
        val generated = AccountInfo(
            address = address,
            provider = Provider.STALWART,
            protocols = StalwartAcceptanceProfile.JMAP_ONLY.protocols,
            credentialReadiness = CredentialReadiness.READY,
            providerAccountId = "generated-id",
        )
        val existing = ProviderIdentitySnapshot(
            provider = Provider.STALWART,
            address = "existing@local.test",
            providerAccountId = "existing-id",
        )

        assertEquals(
            GeneratedAccountCleanupIdentity(generated, "generated-id"),
            recoverGeneratedAccountCleanupIdentity(
                run = run,
                baseline = listOf(existing),
                provider = Provider.STALWART,
                address = address,
                inventory = listOf(generated),
            ),
        )
        assertNull(
            recoverGeneratedAccountCleanupIdentity(
                run = run,
                baseline = listOf(
                    existing,
                    ProviderIdentitySnapshot(
                        provider = Provider.STALWART,
                        address = address,
                        providerAccountId = "generated-id",
                    ),
                ),
                provider = Provider.STALWART,
                address = address,
                inventory = listOf(generated),
            ),
            "A provider identity present in the baseline must never be selected for deletion",
        )
        val baselineAtSameAddress = ProviderIdentitySnapshot(
            provider = Provider.STALWART,
            address = address,
            providerAccountId = "baseline-id",
        )
        assertEquals(
            GeneratedAccountCleanupIdentity(generated, "generated-id"),
            recoverGeneratedAccountCleanupIdentity(
                run = run,
                baseline = listOf(existing, baselineAtSameAddress),
                provider = Provider.STALWART,
                address = address,
                inventory = listOf(
                    generated.copy(providerAccountId = "baseline-id"),
                    generated,
                ),
            ),
            "Recovery may select only the generated provider identity absent from the baseline",
        )
        assertNull(
            recoverGeneratedAccountCleanupIdentity(
                run = run,
                baseline = listOf(existing),
                provider = Provider.STALWART,
                address = address,
                inventory = listOf(
                    generated.copy(address = run.accountAddress(StalwartAcceptanceProfile.SMTP_ONLY)),
                ),
            ),
        )
        assertNull(
            recoverGeneratedAccountCleanupIdentity(
                run = run,
                baseline = listOf(existing),
                provider = Provider.STALWART,
                address = address,
                inventory = listOf(generated.copy(providerAccountId = null)),
            ),
        )
        assertFailsWith<IllegalStateException> {
            recoverGeneratedAccountCleanupIdentity(
                run = run,
                baseline = listOf(existing),
                provider = Provider.STALWART,
                address = address,
                inventory = listOf(
                    generated,
                    generated.copy(providerAccountId = "another-generated-id"),
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            recoverGeneratedAccountCleanupIdentity(
                run = run,
                baseline = listOf(existing),
                provider = Provider.STALWART,
                address = "not-run-owned@local.test",
                inventory = listOf(generated),
            )
        }
    }

    @Test
    fun cancelledWorkflowRunsCleanupNonCancellablyAndKeepsTheOriginalFailure() {
        val original = CancellationException("workflow cancelled")
        val cleanupFailure = IllegalStateException("cleanup failed")
        var cleanupCompleted = false

        val thrown = assertFailsWith<CancellationException> {
            runBlocking {
                currentCoroutineContext().cancel(original)
                try {
                    yield()
                } finally {
                    runAcceptanceCleanup(original) {
                        delay(1)
                        cleanupCompleted = true
                        throw cleanupFailure
                    }
                }
            }
        }

        assertSame(original, thrown)
        assertTrue(cleanupCompleted)
        assertContentEquals(arrayOf(cleanupFailure), thrown.suppressed)
    }

    @Test
    fun authenticationProtocolsAndPrimaryProtocolAreDerivedFromTheSelectedProfile() {
        val dovecot = generatedAccount(Provider.DOVECOT)
        val jmapOnly = generatedStalwartAccount(StalwartAcceptanceProfile.JMAP_ONLY)
        val smtpOnly = generatedStalwartAccount(StalwartAcceptanceProfile.SMTP_ONLY)
        val jmapSmtp = generatedStalwartAccount(StalwartAcceptanceProfile.JMAP_SMTP)

        assertEquals(
            listOf(
                AuthenticationProtocol.IMAP,
                AuthenticationProtocol.POP3,
                AuthenticationProtocol.SMTP,
                AuthenticationProtocol.OAUTH_IMAP,
                AuthenticationProtocol.OAUTH_SMTP,
            ),
            dovecot.authenticationProtocols(),
        )
        assertEquals(AuthenticationProtocol.IMAP, dovecot.primaryAuthenticationProtocol())
        val dovecotSmtpOnly = dovecot.copy(protocols = listOf(MailProtocol.SMTP))
        assertEquals(
            listOf(AuthenticationProtocol.SMTP, AuthenticationProtocol.OAUTH_SMTP),
            dovecotSmtpOnly.authenticationProtocols(),
        )
        assertEquals(
            AuthenticationProtocol.SMTP,
            dovecotSmtpOnly.primaryAuthenticationProtocol(),
        )
        assertEquals(listOf(AuthenticationProtocol.JMAP), jmapOnly.authenticationProtocols())
        assertEquals(AuthenticationProtocol.JMAP, jmapOnly.primaryAuthenticationProtocol())
        assertEquals(listOf(AuthenticationProtocol.SMTP), smtpOnly.authenticationProtocols())
        assertEquals(AuthenticationProtocol.SMTP, smtpOnly.primaryAuthenticationProtocol())
        assertEquals(
            listOf(AuthenticationProtocol.JMAP, AuthenticationProtocol.SMTP),
            jmapSmtp.authenticationProtocols(),
        )
        assertEquals(AuthenticationProtocol.JMAP, jmapSmtp.primaryAuthenticationProtocol())
    }

    @Test
    fun profileErrorsAndGeneratedIdCountsRequireExactEvidence() {
        requireProfileBadRequest(
            DashboardApiError("bad_request", "SMTP is not enabled for this Stalwart Account"),
            "SMTP is not enabled",
        )
        assertFailsWith<IllegalStateException> {
            requireProfileBadRequest(
                DashboardApiError("internal_error", "SMTP is not enabled"),
                "SMTP is not enabled",
            )
        }
        assertFailsWith<IllegalStateException> {
            requireProfileBadRequest(
                DashboardApiError("bad_request", "unrelated"),
                "SMTP is not enabled",
            )
        }

        requireGeneratedMessageIds(
            GenerateMessageResponse(
                messageIds = listOf("message-id"),
                operation = OperationResponse(true, "Appended 1 message"),
            ),
            expectedCount = 1,
        )
        requireGeneratedMessageIds(
            GenerateMessageResponse(
                messageIds = emptyList(),
                operation = OperationResponse(true, "Delivered 1 message"),
            ),
            expectedCount = 0,
        )
        assertFailsWith<IllegalStateException> {
            requireGeneratedMessageIds(
                GenerateMessageResponse(
                    messageIds = emptyList(),
                    operation = OperationResponse(true, "Appended 1 message"),
                ),
                expectedCount = 1,
            )
        }
    }

    @Test
    fun runnerCaptureOrComparisonExecutesOnlyWhenExplicitlySelected() = runBlocking {
        val mode = System.getenv("DASHBOARD_SINGLE_STACK_PRESERVATION_MODE") ?: return@runBlocking
        require(mode == "capture" || mode == "compare") {
            "DASHBOARD_SINGLE_STACK_PRESERVATION_MODE must be capture or compare"
        }
        val selected = SingleStackAcceptanceEnvironment.load()
        LocalDashboardBackend.production(
            repositoryRoot = selected.repositoryRoot,
            environment = System.getenv(),
        ).use { backend ->
            val inventory = backend.listAccounts()
            check(inventory.providerStatuses.all { it.availability == ProviderAvailability.READY }) {
                "Both root providers must be ready for preservation capture/comparison"
            }
            if (mode == "capture") {
                selected.writeSnapshot(selected.capturePreservation(inventory.accounts))
            } else {
                selected.assertPreserved(selected.readSnapshot(), inventory.accounts)
            }
        }
    }

    @Test
    fun selectedEnvironmentRequiresExplicitOptInPrimaryCheckoutAndExactEndpoints() {
        TestRoot().use { fixture ->
            assertFailsWith<IllegalArgumentException> {
                SingleStackAcceptanceEnvironment.load(
                    environment = fixture.environment() - LIVE_KEY,
                    repositoryRoot = fixture.root,
                    commandRunner = fixture.runner,
                )
            }
            assertFailsWith<IllegalArgumentException> {
                SingleStackAcceptanceEnvironment.load(
                    environment = fixture.environment().toMutableMap().apply {
                        this["DASHBOARD_SINGLE_STACK_STALWART_JMAP_ENDPOINT"] =
                            "http://127.0.0.1:18443"
                    },
                    repositoryRoot = fixture.root,
                    commandRunner = fixture.runner,
                )
            }
            assertFailsWith<IllegalArgumentException> {
                SingleStackAcceptanceEnvironment.load(
                    environment = fixture.environment(),
                    repositoryRoot = fixture.root,
                    commandRunner = fixture.runner.copy(primaryCheckout = false),
                )
            }

            val selected = SingleStackAcceptanceEnvironment.load(
                environment = fixture.environment(),
                repositoryRoot = fixture.root,
                commandRunner = fixture.runner,
            )

            assertEquals(fixture.root, selected.repositoryRoot)
            assertEquals(fixture.prefix, selected.run.prefix)
        }
    }

    @Test
    fun existingUsersIncludingAnIntentionallyEmptyFileArePreservedByteForByte() {
        TestRoot(users = ByteArray(0)).use { fixture ->
            val environment = fixture.load()
            val snapshot = environment.capturePreservation(fixture.accounts)

            environment.assertPreserved(snapshot, fixture.accounts)

            fixture.users.writeBytes(fixture.defaults.readBytes())
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(snapshot, fixture.accounts)
            }
        }
    }

    @Test
    fun absentUsersMayOnlyBecomeTheExactNineBootstrappedDefaults() {
        TestRoot(users = null).use { fixture ->
            val environment = fixture.load()
            val snapshot = environment.capturePreservation(fixture.accounts)
            assertFalse(snapshot.usersInitiallyExisted)

            fixture.users.writeBytes(fixture.defaults.readBytes())
            environment.assertPreserved(snapshot, fixture.accounts)

            fixture.users.writeText("unexpected@local.test:{PLAIN}password::::::\n")
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(snapshot, fixture.accounts)
            }
        }
    }

    @Test
    fun snapshotDetectsChangesToPreExistingMailProviderMigrationAndComposeState() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val snapshot = environment.capturePreservation(fixture.accounts)

            fixture.preExistingMail.writeText("changed")
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(snapshot, fixture.accounts)
            }
            fixture.preExistingMail.writeText("original")

            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(
                    snapshot,
                    fixture.accounts.filterNot { it.provider == Provider.STALWART },
                )
            }
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(
                    snapshot,
                    fixture.accounts,
                    commandRunner = fixture.runner.copy(composeContainerSuffix = "changed"),
                )
            }

            fixture.currentReceipt.writeText("{}\n")
            assertFailsWith<IllegalStateException> {
                environment.assertPreserved(snapshot, fixture.accounts)
            }
        }
    }

    @Test
    fun persistedSnapshotRoundTripsForTheRunnerFinallyComparison() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val captured = environment.capturePreservation(fixture.accounts)

            environment.writeSnapshot(captured)
            val restored = environment.readSnapshot()

            assertEquals(captured, restored)
            environment.assertPreserved(restored, fixture.accounts)
        }
    }

    @Test
    fun catalogCleanupRemovesOnlyAnAcceptanceCreatedEmptyCatalog() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val snapshot = environment.capturePreservation(fixture.accounts)
            val catalog = fixture.root.resolve("debug-dashboard/.runtime/dashboard/accounts.json")
            catalog.parent.createDirectories()
            catalog.writeText("{\"version\":2,\"accounts\":[]}\n")

            environment.removeGeneratedCatalogIfInitiallyAbsent(snapshot)

            assertFalse(catalog.exists())
            catalog.writeText(
                "{\"version\":2,\"accounts\":[{" +
                    "\"provider\":\"DOVECOT\",\"address\":\"existing@local.test\"}]}\n",
            )
            assertFailsWith<IllegalStateException> {
                environment.removeGeneratedCatalogIfInitiallyAbsent(snapshot)
            }
            assertTrue(catalog.exists())
        }
    }

    @Test
    fun cleanupRejectsAnythingOutsideTheUniqueRunPrefixAndPurgesOnlyItsMaildir() {
        TestRoot().use { fixture ->
            val environment = fixture.load()
            val generated = environment.run.accountAddress(Provider.DOVECOT)
            val generatedRoot = fixture.root.resolve("vmail/$generated")
            generatedRoot.resolve("Maildir/new").createDirectories()
            generatedRoot.resolve("Maildir/new/message").writeText("generated")

            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAddress("existing@local.test")
            }
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedFolder("existing-folder")
            }
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAccount(fixture.accounts.first())
            }
            assertFailsWith<IllegalArgumentException> {
                environment.requireGeneratedAccount(
                    AccountInfo(
                        address = environment.run.accountAddress(Provider.STALWART),
                        provider = Provider.STALWART,
                        protocols = listOf(MailProtocol.JMAP),
                        credentialReadiness = CredentialReadiness.READY,
                        providerAccountId = null,
                    ),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                environment.purgeGeneratedDovecotMaildir("existing@local.test")
            }

            environment.purgeGeneratedDovecotMaildir(generated)

            assertFalse(generatedRoot.exists())
            assertTrue(fixture.preExistingMail.exists())
            assertEquals("original", Files.readString(fixture.preExistingMail))
        }
    }

    @Test
    fun generatedMessagesResolveOpaqueLocalizedFoldersByIdentityAndSubject() {
        val inbox = FolderInfo("opaque-inbox-id", "Boîte de réception", 3, 3)
        val copyTarget = FolderInfo("opaque-copy-id", "Acceptance copy", 1, 1)
        val trash = FolderInfo("opaque-trash-id", "Deleted Items", 1, 1)
        val eml = message("eml-id", inbox.id, "acceptance EML")
        val text = message("text-id", inbox.id, "acceptance text")
        val random = message("random-id", inbox.id, "acceptance random")
        val copied = message("shared-message-id", copyTarget.id, "acceptance random")
        val trashed = message("shared-message-id", trash.id, "acceptance random")
        val initial = listOf(
            inbox to listOf(eml, text, random),
            trash to emptyList(),
        )
        val afterTrash = listOf(
            inbox to listOf(eml, text),
            copyTarget to listOf(copied),
            trash to listOf(trashed),
        )

        assertEquals(
            inbox,
            requireSingleFolderContainingMessageIds(
                initial,
                setOf(eml.id, text.id, random.id),
            ),
        )
        assertEquals(
            trash to trashed,
            requireUniqueMessageBySubject(
                afterTrash,
                "acceptance random",
                excludedFolderIds = setOf(copyTarget.id),
            ),
        )
    }

    @Test
    fun globalAndAccountLogEvidenceRejectsShapeOnlyResponses() {
        val services = listOf(
            LogService.DOVECOT,
            LogService.POSTFIX,
            LogService.OAUTH2,
            LogService.STALWART,
        )
        val serviceLogs = services.associateWith { service ->
            LogResponse(service, lines = listOf("${service.name.lowercase()} ready"))
        }
        val allLogs = LogResponse(
            LogService.ALL,
            lines = services.map { service ->
                "[${service.name.lowercase()}] ${service.name.lowercase()} ready"
            },
        )

        requireFunctionalGlobalLogs(allLogs, serviceLogs)
        assertFailsWith<IllegalStateException> {
            requireFunctionalGlobalLogs(allLogs.copy(lines = emptyList()), serviceLogs)
        }
        assertFailsWith<IllegalStateException> {
            requireFunctionalGlobalLogs(
                allLogs.copy(lines = allLogs.lines.filterNot { it.startsWith("[stalwart]") }),
                serviceLogs,
            )
        }
        assertFailsWith<IllegalStateException> {
            requireFunctionalGlobalLogs(
                allLogs,
                serviceLogs + (LogService.POSTFIX to LogResponse(LogService.POSTFIX, lines = emptyList())),
            )
        }

        val account = AccountInfo(
            address = "acceptance@local.test",
            provider = Provider.DOVECOT,
            protocols = listOf(MailProtocol.IMAP),
            credentialReadiness = CredentialReadiness.READY,
        )
        val correlatedLine = "dovecot | auth: acceptance@local.test succeeded"
        val probe = AuthenticationProbeResponse(
            address = account.address,
            provider = account.provider,
            protocol = AuthenticationProtocol.IMAP,
            success = true,
            providerResponse = "Authentication succeeded",
            correlatedLogs = listOf(correlatedLine),
        )
        val accountLogs = LogResponse(
            service = LogService.DOVECOT,
            account = account.address,
            lines = listOf("[dovecot] $correlatedLine"),
        )

        requireFunctionalAccountLogs(account, accountLogs, probe)
        val oauthBearer = "valid-${account.address}"
        val oauthAccountLogs = accountLogs.copy(
            lines = accountLogs.lines +
                "[oauth2] oauth2-mock | Introspection identity=${account.address} outcome=active",
        )
        requireFunctionalOAuthAccountLogs(
            account = account,
            accountLogs = oauthAccountLogs,
            globalLogs = LogResponse(
                service = LogService.ALL,
                lines = oauthAccountLogs.lines,
            ),
            submittedBearer = oauthBearer,
        )
        assertFailsWith<IllegalStateException> {
            requireFunctionalOAuthAccountLogs(
                account = account,
                accountLogs = accountLogs,
                globalLogs = LogResponse(LogService.ALL, lines = accountLogs.lines),
                submittedBearer = oauthBearer,
            )
        }
        assertFailsWith<IllegalStateException> {
            requireFunctionalOAuthAccountLogs(
                account = account,
                accountLogs = oauthAccountLogs.copy(lines = oauthAccountLogs.lines + oauthBearer),
                globalLogs = LogResponse(LogService.ALL, lines = oauthAccountLogs.lines),
                submittedBearer = oauthBearer,
            )
        }
        val stalwartAccount = generatedAccount(Provider.STALWART)
        val stalwartLine = "stalwart | accountId = 42 authentication rejected"
        requireFunctionalAccountLogs(
            stalwartAccount,
            LogResponse(
                service = LogService.STALWART,
                account = stalwartAccount.address,
                lines = listOf(stalwartLine),
            ),
            probe.copy(
                address = stalwartAccount.address,
                provider = Provider.STALWART,
                protocol = AuthenticationProtocol.JMAP,
                correlatedLogs = listOf(stalwartLine),
            ),
        )
        assertFailsWith<IllegalStateException> {
            requireFunctionalAccountLogs(account, accountLogs.copy(lines = emptyList()), probe)
        }
        assertFailsWith<IllegalStateException> {
            requireFunctionalAccountLogs(
                account,
                accountLogs.copy(lines = listOf("[dovecot] unrelated account")),
                probe,
            )
        }
    }

    @Test
    fun deletedCredentialVerifierUsesProviderEndpointsAndRejectsWeakEvidence() {
        val attempts = mutableListOf<ProviderAuthenticationAttempt>()
        val verifier = DirectDeletedAccountCredentialVerifier(
            ProviderAuthenticationProbe(
                ProviderAuthenticationConnector { attempt ->
                    attempts += attempt
                    ProviderAuthenticationTransportOutcome.MissingAccount("Account was not found")
                },
            ),
        )
        val dovecot = generatedAccount(Provider.DOVECOT)
        val stalwart = generatedAccount(Provider.STALWART)

        runBlocking {
            verifier.requireRejected(dovecot, "former-dovecot-password")
            verifier.requireRejected(stalwart, "former-stalwart-password")
        }

        assertEquals(ProviderAuthenticationProtocol.IMAP, attempts[0].protocol)
        assertEquals(1143, attempts[0].endpoint.port)
        assertTrue(attempts[0].endpoint.startTls)
        assertEquals(ProviderAuthenticationProtocol.SMTP, attempts[1].protocol)
        assertEquals(8587, attempts[1].endpoint.port)
        assertFalse(attempts[1].endpoint.startTls)
        assertTrue(attempts.all { it.address.endsWith("@local.test") })

        val genericWrongPassword = DirectDeletedAccountCredentialVerifier(
            ProviderAuthenticationProbe(
                ProviderAuthenticationConnector {
                    ProviderAuthenticationTransportOutcome.WrongPassword("Authentication rejected")
                },
            ),
        )
        assertFailsWith<IllegalStateException> {
            runBlocking { genericWrongPassword.requireRejected(dovecot, "former-password") }
        }
        assertFailsWith<IllegalStateException> {
            runBlocking { genericWrongPassword.requireRejected(stalwart, "former-password") }
        }

        val canonicalRejections = DirectDeletedAccountCredentialVerifier(
            ProviderAuthenticationProbe(
                ProviderAuthenticationConnector { attempt ->
                    when (attempt.protocol) {
                        ProviderAuthenticationProtocol.IMAP ->
                            ProviderAuthenticationTransportOutcome.WrongPassword(
                                "[AUTHENTICATIONFAILED] Authentication failed",
                            )
                        ProviderAuthenticationProtocol.SMTP ->
                            ProviderAuthenticationTransportOutcome.WrongPassword(
                                "535 5.7.8 Authentication credentials invalid",
                            )
                        ProviderAuthenticationProtocol.POP3 -> error("Unexpected POP3 deletion probe")
                    }
                },
            ),
        )
        runBlocking {
            canonicalRejections.requireRejected(dovecot, "former-dovecot-password")
            canonicalRejections.requireRejected(stalwart, "former-stalwart-password")
        }

        val authenticated = DirectDeletedAccountCredentialVerifier(
            ProviderAuthenticationProbe(
                ProviderAuthenticationConnector {
                    ProviderAuthenticationTransportOutcome.Authenticated("Unexpected success")
                },
            ),
        )
        assertFailsWith<IllegalStateException> {
            runBlocking { authenticated.requireRejected(dovecot, "still-valid-password") }
        }

        val unavailable = DirectDeletedAccountCredentialVerifier(
            ProviderAuthenticationProbe(
                ProviderAuthenticationConnector {
                    ProviderAuthenticationTransportOutcome.Unavailable("Connection refused")
                },
            ),
        )
        assertFailsWith<IllegalStateException> {
            runBlocking { unavailable.requireRejected(stalwart, "unproved-password") }
        }

        val jmapAttempts = mutableListOf<AccountInfo>()
        val jmapOnlyVerifier = DirectDeletedAccountCredentialVerifier(
            probe = ProviderAuthenticationProbe(
                ProviderAuthenticationConnector { error("SMTP must not probe a JMAP-only profile") },
            ),
            jmapRejectionProbe = { account, _ ->
                jmapAttempts += account
                mail.sandbox.dashboard.server.provider.AuthenticationOutcome.MissingAccount(
                    "JMAP ordinary Account was not found",
                )
            },
        )
        val jmapOnly = generatedStalwartAccount(StalwartAcceptanceProfile.JMAP_ONLY)
        runBlocking { jmapOnlyVerifier.requireRejected(jmapOnly, "former-jmap-password") }
        assertEquals(listOf(jmapOnly), jmapAttempts)
    }

    @Test
    fun liveRunnerIsOptInSelectsOnlyTheLiveClassAndNeverStartsCompose() {
        val repositoryRoot = generateSequence(
            Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize(),
            Path::getParent,
        ).take(6).first { candidate ->
            Files.isRegularFile(candidate.resolve("docker-compose.yml"))
        }
        val script = Files.readString(repositoryRoot.resolve("debug-dashboard/run-live-acceptance.sh"))

        assertTrue("DASHBOARD_SINGLE_STACK_LIVE_TESTS" in script)
        assertTrue("SingleStackUsabilityLiveTest" in script)
        assertTrue("SingleStackPreservationTest" in script)
        assertTrue("trap" in script)
        assertFalse(Regex("docker\\s+compose(?:\\s+-f\\s+[^\\s]+)*\\s+up").containsMatchIn(script))
        assertFalse("docker-compose up" in script)
        assertFalse("COMPOSE_PROJECT_NAME=" in script)
    }

    private fun generatedAccount(provider: Provider): AccountInfo = AccountInfo(
        address = "dashboard-acceptance-${provider.name.lowercase()}@local.test",
        provider = provider,
        protocols = when (provider) {
            Provider.DOVECOT -> listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP)
            Provider.STALWART -> listOf(MailProtocol.JMAP, MailProtocol.SMTP)
        },
        credentialReadiness = CredentialReadiness.READY,
        providerAccountId = if (provider == Provider.STALWART) "account-id" else null,
    )

    private fun generatedStalwartAccount(profile: StalwartAcceptanceProfile): AccountInfo =
        AccountInfo(
            address = "dashboard-acceptance-stalwart-${profile.slug}@local.test",
            provider = Provider.STALWART,
            protocols = profile.protocols,
            credentialReadiness = CredentialReadiness.READY,
            providerAccountId = "account-id-${profile.slug}",
        )

    private class TestRoot(
        users: ByteArray? = canonicalUsers("existing@local.test", "existing-password"),
    ) : AutoCloseable {
        val root: Path = Files.createTempDirectory("single-stack-preservation-")
            .toAbsolutePath()
            .normalize()
        val prefix = "dashboard-acceptance-1786380000-a1b2c3d4"
        val users = root.resolve("config/users")
        val defaults = root.resolve("config/users.defaults")
        val currentReceipt = root.resolve("debug-dashboard/.runtime/stalwart/current.json")
        private val sourceReceipt = root.resolve(
            "debug-dashboard/.runtime/stalwart-migration/latest-source.json",
        )
        private val retainedSnapshot = root.resolve(
            "captures/debug-dashboard/stalwart-v015/backups/" +
                "stalwart-v015-20260810T120000Z-a1b2c3d4",
        )
        val preExistingMail = root.resolve("vmail/existing@local.test/Maildir/cur/message")
        val accounts = listOf(
            AccountInfo(
                address = "existing@local.test",
                provider = Provider.DOVECOT,
                protocols = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP),
                credentialReadiness = CredentialReadiness.READY,
            ),
            AccountInfo(
                address = "stalwart-existing@local.test",
                provider = Provider.STALWART,
                protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                credentialReadiness = CredentialReadiness.PASSWORD_REQUIRED,
                providerAccountId = "42",
            ),
        )
        val runner = FakeCommandRunner(root)

        init {
            root.resolve(".git").createDirectories()
            root.resolve("docker-compose.yml").writeText("services: {}\n")
            defaults.parent.createDirectories()
            defaults.writeBytes(DEFAULT_USERS)
            if (users != null) this.users.writeBytes(users)
            preExistingMail.parent.createDirectories()
            preExistingMail.writeText("original")
            currentReceipt.parent.createDirectories()
            currentReceipt.writeText("{\"schema\":\"mail-sandbox.stalwart-current-runtime.v1\"}\n")
            retainedSnapshot.createDirectories()
            sourceReceipt.parent.createDirectories()
            sourceReceipt.writeText(
                """{"payload":{"backup":{"root":"$retainedSnapshot"}},"payload_sha256":"fake-validated-by-runner"}
                """.trimIndent(),
            )
            root.resolve("debug-dashboard/.runtime/acceptance/$prefix").createDirectories()
        }

        fun environment(): Map<String, String> = SingleStackAcceptanceEnvironment.EXACT_ENDPOINTS +
            mapOf(
                LIVE_KEY to "1",
                "DASHBOARD_SINGLE_STACK_RUN_PREFIX" to prefix,
                "DASHBOARD_SINGLE_STACK_SNAPSHOT" to root.resolve(
                    "debug-dashboard/.runtime/acceptance/$prefix/baseline.json",
                ).toString(),
            )

        fun load(): SingleStackAcceptanceEnvironment = SingleStackAcceptanceEnvironment.load(
            environment = environment(),
            repositoryRoot = root,
            commandRunner = runner,
        )

        override fun close() {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private data class FakeCommandRunner(
        val root: Path,
        val primaryCheckout: Boolean = true,
        val composeContainerSuffix: String = "original",
    ) : SingleStackCommandRunner {
        override fun run(argv: List<String>): SingleStackCommandResult = when {
            argv.takeLast(2) == listOf("rev-parse", "--show-toplevel") ->
                success(if (primaryCheckout) root.toString() else root.resolve("worktree").toString())
            argv.takeLast(2) == listOf("rev-parse", "--git-common-dir") ->
                success(if (primaryCheckout) root.resolve(".git").toString() else root.resolve("common.git").toString())
            argv.any { it.endsWith("/stalwart_runtime_state.py") } -> success("current")
            argv.any { it.endsWith("/capture_stalwart_v015.py") } -> success("verified")
            argv.firstOrNull() == "docker" -> success(
                """[
                  {"ID":"dovecot-$composeContainerSuffix","Project":"mail-sandbox","Service":"dovecot"},
                  {"ID":"postfix-$composeContainerSuffix","Project":"mail-sandbox","Service":"postfix"},
                  {"ID":"oauth-$composeContainerSuffix","Project":"mail-sandbox","Service":"oauth2-mock"},
                  {"ID":"stalwart-$composeContainerSuffix","Project":"mail-sandbox","Service":"stalwart"}
                ]
                """.trimIndent(),
            )
            else -> SingleStackCommandResult(2, "", "unexpected command: $argv")
        }

        private fun success(stdout: String) = SingleStackCommandResult(0, "$stdout\n", "")
    }

    private companion object {
        const val LIVE_KEY = "DASHBOARD_SINGLE_STACK_LIVE_TESTS"
        val DEFAULT_USERS = (1..9).joinToString(separator = "") { index ->
            "seed-$index@local.test:{PLAIN}password-$index::::::\n"
        }.toByteArray()

        fun canonicalUsers(address: String, password: String): ByteArray =
            "$address:{PLAIN}$password::::::\n".toByteArray()

        fun message(id: String, folderId: String, subject: String) = MessageSummary(
            id = id,
            folderId = folderId,
            mutationState = "state-$id",
            subject = subject,
            fromAddress = "acceptance-sender@local.test",
            receivedAt = "2026-08-11T12:00:00Z",
            isRead = false,
            isFlagged = false,
        )
    }
}
