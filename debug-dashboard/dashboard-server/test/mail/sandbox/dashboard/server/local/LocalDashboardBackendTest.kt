package mail.sandbox.dashboard.server.local

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.contract.ProviderStatus

class LocalDashboardBackendTest {
    @Test
    fun stalwartStartupStateUsesFixedValuesAndFailsClosedOnMalformedInput() {
        assertEquals(
            listOf(
                "CURRENT",
                "MIGRATION_REQUIRED",
                "INITIALIZATION_FAILED",
                "INVALID",
                "UNAVAILABLE",
            ),
            StalwartStartupState.entries.map(StalwartStartupState::name),
        )
        assertEquals(StalwartStartupState.UNAVAILABLE, StalwartStartupState.fromEnvironment(null))
        assertEquals(
            StalwartStartupState.CURRENT,
            StalwartStartupState.fromEnvironment("CURRENT"),
        )
        assertEquals(
            StalwartStartupState.MIGRATION_REQUIRED,
            StalwartStartupState.fromEnvironment("MIGRATION_REQUIRED"),
        )
        listOf("", "current", "FRESH", "READY", " CURRENT ", "unknown").forEach { value ->
            assertEquals(
                StalwartStartupState.INVALID,
                StalwartStartupState.fromEnvironment(value),
                "Expected malformed launcher state '$value' to fail closed",
            )
        }
        assertEquals(null, StalwartStartupState.CURRENT.providerStatus())
        assertEquals(
            ProviderAvailability.UPGRADE_REQUIRED,
            StalwartStartupState.MIGRATION_REQUIRED.providerStatus()?.availability,
        )
        listOf(
            StalwartStartupState.INITIALIZATION_FAILED,
            StalwartStartupState.INVALID,
            StalwartStartupState.UNAVAILABLE,
        ).forEach { state ->
            assertEquals(ProviderAvailability.UNAVAILABLE, state.providerStatus()?.availability)
        }
    }

    @Test
    fun startupStatusBlocksOnlyStalwartAndRetainsItsCachedAccountsAsStale() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            accounts += AccountInfo(
                address = "live-dovecot@local.test",
                provider = Provider.DOVECOT,
                protocols = listOf(MailProtocol.IMAP),
                credentialReadiness = CredentialReadiness.READY,
            )
        }
        val stalwart = RecordingProvider(Provider.STALWART).apply {
            beforeList = { error("A migration-required provider must not be contacted") }
        }
        val startupStatus = requireNotNull(
            StalwartStartupState.MIGRATION_REQUIRED.providerStatus(),
        )
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
            cachedAccounts = {
                listOf(
                    LocalAccountRecord(
                        provider = Provider.STALWART,
                        address = "cached-stalwart@local.test",
                        password = "cached-password",
                        protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                        providerAccountId = "cached-id",
                    ),
                )
            },
            startupProviderStatuses = mapOf(Provider.STALWART to startupStatus),
        )

        val response = backend.listAccounts()

        assertEquals(
            listOf("cached-stalwart@local.test", "live-dovecot@local.test"),
            response.accounts.map(AccountInfo::address),
        )
        assertTrue(response.accounts.first().stale)
        assertEquals(
            listOf(ProviderAvailability.READY, ProviderAvailability.UPGRADE_REQUIRED),
            response.providerStatuses.map(ProviderStatus::availability),
        )
        assertFailsWith<IllegalStateException> {
            backend.createAccount(
                CreateAccountRequest(
                    address = "blocked@local.test",
                    password = "password",
                    provider = Provider.STALWART,
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                ),
            )
        }
        Unit
    }

    @Test
    fun providerListingsStartConcurrentlyWhileResultsStayDeterministic() = runBlocking {
        val dovecotStarted = CompletableDeferred<Unit>()
        val stalwartStarted = CompletableDeferred<Unit>()
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            beforeList = {
                dovecotStarted.complete(Unit)
                withTimeout(250) { stalwartStarted.await() }
            }
            accounts += AccountInfo(
                address = "zeta@local.test",
                provider = Provider.DOVECOT,
                protocols = listOf(MailProtocol.IMAP),
                credentialReadiness = CredentialReadiness.READY,
            )
        }
        val stalwart = RecordingProvider(Provider.STALWART).apply {
            beforeList = {
                stalwartStarted.complete(Unit)
                withTimeout(250) { dovecotStarted.await() }
            }
            accounts += AccountInfo(
                address = "alpha@local.test",
                provider = Provider.STALWART,
                protocols = listOf(MailProtocol.JMAP),
                credentialReadiness = CredentialReadiness.READY,
                providerAccountId = "stalwart-alpha",
            )
        }
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
        )

        val response = backend.listAccounts()

        assertEquals(
            listOf("alpha@local.test", "zeta@local.test"),
            response.accounts.map(AccountInfo::address),
        )
        assertEquals(
            Provider.entries,
            response.providerStatuses.map(ProviderStatus::provider),
        )
    }

    @Test
    fun providerDeadlinePreservesHealthyResultsAndTimedOutProviderFallback() = runBlocking {
        val dovecotStarted = CompletableDeferred<Unit>()
        val dovecotInterrupted = CompletableDeferred<Unit>()
        val stalwartStarted = CompletableDeferred<Unit>()
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            beforeList = {
                dovecotStarted.complete(Unit)
                try {
                    Thread.sleep(750)
                } finally {
                    dovecotInterrupted.complete(Unit)
                }
            }
        }
        val stalwart = RecordingProvider(Provider.STALWART).apply {
            beforeList = { stalwartStarted.complete(Unit) }
            accounts += AccountInfo(
                address = "live-stalwart@local.test",
                provider = Provider.STALWART,
                protocols = listOf(MailProtocol.JMAP),
                credentialReadiness = CredentialReadiness.READY,
                providerAccountId = "live-stalwart",
            )
        }
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
            cachedAccounts = {
                listOf(
                    LocalAccountRecord(
                        provider = Provider.DOVECOT,
                        address = "cached-dovecot@local.test",
                        password = "cached-password",
                        protocols = listOf(MailProtocol.IMAP),
                    ),
                )
            },
            providerListTimeoutMillis = 50,
        )

        val response = withTimeout(500) { backend.listAccounts() }

        assertTrue(dovecotStarted.isCompleted)
        assertTrue(stalwartStarted.isCompleted)
        withTimeout(500) { dovecotInterrupted.await() }
        assertEquals(
            listOf("cached-dovecot@local.test", "live-stalwart@local.test"),
            response.accounts.map(AccountInfo::address),
        )
        assertTrue(response.accounts.first().stale)
        assertFalse(response.accounts.last().stale)
        assertEquals(
            listOf(ProviderAvailability.UNAVAILABLE, ProviderAvailability.READY),
            response.providerStatuses.map(ProviderStatus::availability),
        )
        assertTrue("timed out" in response.providerStatuses.first().message.orEmpty())
        assertEquals(Provider.entries, response.providerStatuses.map(ProviderStatus::provider))
    }

    @Test
    fun parentCancellationStopsEveryConcurrentProviderListing() = runBlocking {
        val dovecotStarted = CompletableDeferred<Unit>()
        val stalwartStarted = CompletableDeferred<Unit>()
        val dovecotCancelled = CompletableDeferred<Unit>()
        val stalwartCancelled = CompletableDeferred<Unit>()
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            beforeList = {
                dovecotStarted.complete(Unit)
                try {
                    awaitCancellation()
                } finally {
                    dovecotCancelled.complete(Unit)
                }
            }
        }
        val stalwart = RecordingProvider(Provider.STALWART).apply {
            beforeList = {
                stalwartStarted.complete(Unit)
                try {
                    awaitCancellation()
                } finally {
                    stalwartCancelled.complete(Unit)
                }
            }
        }
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
            providerListTimeoutMillis = 10_000,
        )
        val listing = async { backend.listAccounts() }
        withTimeout(500) {
            dovecotStarted.await()
            stalwartStarted.await()
        }

        listing.cancel(CancellationException("caller stopped listing"))

        val cancellation = assertFailsWith<CancellationException> { listing.await() }
        assertEquals("caller stopped listing", cancellation.message)
        withTimeout(500) {
            dovecotCancelled.await()
            stalwartCancelled.await()
        }
    }

    @Test
    fun providerOwnedTimeoutDoesNotCancelAHealthySibling() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            beforeList = { withTimeout(25) { awaitCancellation() } }
        }
        val stalwart = RecordingProvider(Provider.STALWART).apply {
            accounts += AccountInfo(
                address = "live-stalwart@local.test",
                provider = Provider.STALWART,
                protocols = listOf(MailProtocol.JMAP),
                credentialReadiness = CredentialReadiness.READY,
                providerAccountId = "live-stalwart",
            )
        }
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
            cachedAccounts = {
                listOf(
                    LocalAccountRecord(
                        provider = Provider.DOVECOT,
                        address = "cached-dovecot@local.test",
                        password = "cached-password",
                        protocols = listOf(MailProtocol.IMAP),
                    ),
                )
            },
            providerListTimeoutMillis = 500,
        )

        val response = backend.listAccounts()

        assertEquals(
            listOf(ProviderAvailability.UNAVAILABLE, ProviderAvailability.READY),
            response.providerStatuses.map(ProviderStatus::availability),
        )
        assertEquals(
            listOf("cached-dovecot@local.test", "live-stalwart@local.test"),
            response.accounts.map(AccountInfo::address),
        )
        assertTrue(response.accounts.first().stale)
    }

    @Test
    fun internalProbeRedactionMetadataDoesNotRenderSecrets() {
        val secret = "internal-redaction-canary"
        val result = LocalAuthenticationProbeResult(
            response = AuthenticationProbeResponse(
                address = "dev@local.test",
                provider = Provider.DOVECOT,
                protocol = AuthenticationProtocol.IMAP,
                success = false,
                providerResponse = "failed",
                correlatedLogs = emptyList(),
            ),
            secretsToRedact = listOf(secret),
        )

        assertFalse(secret in result.toString())
    }

    @Test
    fun combinesProvidersAndDispatchesAccountCreationToTheSelectedServer() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT)
        val stalwart = RecordingProvider(Provider.STALWART)
        dovecot.accounts += AccountInfo(
            address = "zeta@local.test",
            provider = Provider.DOVECOT,
            protocols = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP),
            credentialReadiness = CredentialReadiness.READY,
        )
        stalwart.accounts += AccountInfo(
            address = "alpha@local.test",
            provider = Provider.STALWART,
            protocols = listOf(MailProtocol.JMAP),
            credentialReadiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
            providerAccountId = "account-alpha",
        )
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
        )

        assertEquals(
            listOf("alpha@local.test", "zeta@local.test"),
            backend.listAccounts().accounts.map(AccountInfo::address),
        )
        assertEquals(
            listOf(Provider.DOVECOT, Provider.STALWART),
            backend.listAccounts().providerStatuses.map(ProviderStatus::provider),
        )

        val request = CreateAccountRequest(
            address = "new@local.test",
            password = "password",
            provider = Provider.STALWART,
            protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
        )
        assertEquals(request.address, backend.createAccount(request).address)
        assertEquals(listOf(request), stalwart.createdAccounts)
        assertTrue(dovecot.createdAccounts.isEmpty())
    }

    @Test
    fun providerFailuresAreIndependentAndOnlyFailedProviderUsesStaleCatalogProjection() =
        runBlocking {
            val dovecot = RecordingProvider(Provider.DOVECOT).apply {
                listFailure = IllegalStateException("Dovecot unavailable")
            }
            val stalwart = RecordingProvider(Provider.STALWART).apply {
                status = ProviderStatus(
                    provider = Provider.STALWART,
                    availability = ProviderAvailability.DEGRADED,
                    message = "Credential probes unavailable",
                )
                accounts += AccountInfo(
                    address = "live@local.test",
                    provider = Provider.STALWART,
                    protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                    credentialReadiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
                    providerAccountId = "live-id",
                )
            }
            val cached = listOf(
                LocalAccountRecord(
                    provider = Provider.DOVECOT,
                    address = "cached-dove@local.test",
                    password = "cached-password",
                    protocols = listOf(MailProtocol.IMAP),
                ),
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "live@local.test",
                    password = "must-not-override-live",
                    protocols = listOf(MailProtocol.JMAP),
                    providerAccountId = "live-id",
                ),
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "cached-stalwart@local.test",
                    password = null,
                    protocols = listOf(MailProtocol.JMAP),
                    providerAccountId = "cached-id",
                ),
            )
            val backend = LocalDashboardBackend(
                providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
                logSource = RecordingLogs(),
                cachedAccounts = { cached },
            )

            val response = backend.listAccounts()

            assertEquals(
                listOf("cached-dove@local.test", "live@local.test"),
                response.accounts.map(AccountInfo::address),
            )
            val stale = response.accounts.first()
            assertTrue(stale.stale)
            assertEquals(CredentialReadiness.PROVIDER_UNAVAILABLE, stale.credentialReadiness)
            assertEquals(listOf(MailProtocol.IMAP), stale.protocols)
            val live = response.accounts.last()
            assertTrue(!live.stale)
            assertEquals(listOf(MailProtocol.JMAP, MailProtocol.SMTP), live.protocols)
            assertEquals(
                listOf(ProviderAvailability.UNAVAILABLE, ProviderAvailability.DEGRADED),
                response.providerStatuses.map(ProviderStatus::availability),
            )
            assertTrue("Dovecot unavailable" in response.providerStatuses.first().message.orEmpty())
        }

    @Test
    fun providerStatusFailuresAreIndependentAndUseOnlyThatProvidersStaleProjection() =
        runBlocking {
            val dovecot = RecordingProvider(Provider.DOVECOT).apply {
                statusFailure = IllegalStateException("Dovecot status unavailable")
                accounts += AccountInfo(
                    address = "must-not-leak@local.test",
                    provider = Provider.DOVECOT,
                    protocols = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP),
                    credentialReadiness = CredentialReadiness.READY,
                )
            }
            val stalwart = RecordingProvider(Provider.STALWART).apply {
                accounts += AccountInfo(
                    address = "live@local.test",
                    provider = Provider.STALWART,
                    protocols = listOf(MailProtocol.JMAP),
                    credentialReadiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
                    providerAccountId = "live-id",
                )
            }
            val backend = LocalDashboardBackend(
                providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
                logSource = RecordingLogs(),
                cachedAccounts = {
                    listOf(
                        LocalAccountRecord(
                            provider = Provider.DOVECOT,
                            address = "cached@local.test",
                            password = "cached-password",
                            protocols = listOf(MailProtocol.IMAP),
                        ),
                    )
                },
            )

            val response = backend.listAccounts()

            assertEquals(
                listOf("cached@local.test", "live@local.test"),
                response.accounts.map(AccountInfo::address),
            )
            assertEquals(
                listOf(ProviderAvailability.UNAVAILABLE, ProviderAvailability.READY),
                response.providerStatuses.map(ProviderStatus::availability),
            )
            assertTrue(response.accounts.first().stale)
        }

    @Test
    fun cacheFailureCannotHideEitherLiveProviderRegistry() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            accounts += AccountInfo(
                address = "dove@local.test",
                provider = Provider.DOVECOT,
                protocols = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP),
                credentialReadiness = CredentialReadiness.READY,
            )
        }
        val stalwart = RecordingProvider(Provider.STALWART).apply {
            accounts += AccountInfo(
                address = "stalwart@local.test",
                provider = Provider.STALWART,
                protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                credentialReadiness = CredentialReadiness.PASSWORD_REQUIRED,
                providerAccountId = "stalwart-account",
            )
        }
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
            cachedAccounts = { throw IllegalStateException("catalog unavailable") },
        )

        val response = backend.listAccounts()

        assertEquals(
            listOf("dove@local.test", "stalwart@local.test"),
            response.accounts.map(AccountInfo::address),
        )
        assertEquals(
            listOf(ProviderAvailability.READY, ProviderAvailability.READY),
            response.providerStatuses.map(ProviderStatus::availability),
        )
    }

    @Test
    fun providerListingCancellationIsRethrown() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            listFailure = CancellationException("cancel listing")
        }
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot),
            logSource = RecordingLogs(),
        )

        assertFailsWith<CancellationException> { backend.listAccounts() }
        Unit
    }

    @Test
    fun authenticationProbeRunsOnceAndReturnsOnlyNewAccountFilteredLogs() = runBlocking {
        val credential = "wrong-password"
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            probeResponse = "authentication failed for $credential"
        }
        val logs = SequencedProbeLogs(
            listOf("old matching line"),
            listOf("old matching line"),
            listOf("old matching line", "new matching line credential=$credential"),
        )
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot),
            logSource = logs,
            authenticationLogPollDelayMillis = 0,
        )
        val request = AuthenticationProbeRequest(
            address = "dev@local.test",
            provider = Provider.DOVECOT,
            protocol = AuthenticationProtocol.IMAP,
            credentialOverride = credential,
        )

        val response = backend.probeAuthentication(request)

        assertEquals(false, response.success)
        assertEquals(listOf("new matching line credential=[redacted]"), response.correlatedLogs)
        assertEquals("authentication failed for [redacted]", response.providerResponse)
        assertEquals(listOf(request), dovecot.probeRequests)
        assertEquals(3, logs.readCount)
        assertTrue(credential !in response.providerResponse)
        assertTrue(response.correlatedLogs.none { credential in it })
    }

    @Test
    fun authenticationProbeRedactsRememberedCredentialFromResponseAndLogs() = runBlocking {
        val remembered = "remembered-secret-canary"
        val dovecot = RecordingProvider(Provider.DOVECOT).apply {
            probeResponse = "authentication failed credential=$remembered"
            probeSecrets = listOf(remembered)
        }
        val logs = SequencedProbeLogs(
            listOf("old matching line"),
            listOf("new matching line credential=$remembered"),
        )
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot),
            logSource = logs,
            authenticationLogPollDelayMillis = 0,
        )

        val response = backend.probeAuthentication(
            AuthenticationProbeRequest(
                address = "dev@local.test",
                provider = Provider.DOVECOT,
                protocol = AuthenticationProtocol.IMAP,
            ),
        )

        assertEquals("authentication failed credential=[redacted]", response.providerResponse)
        assertEquals(
            listOf("new matching line credential=[redacted]"),
            response.correlatedLogs,
        )
        assertTrue(remembered !in response.toString())
    }

    @Test
    fun authenticationLogPollingIsBoundedWhenNoNewEvidenceArrives() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT)
        val logs = SequencedProbeLogs(*Array(8) { listOf("old matching line") })
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot),
            logSource = logs,
            authenticationLogPollAttempts = 3,
            authenticationLogPollDelayMillis = 0,
        )

        val response = backend.probeAuthentication(
            AuthenticationProbeRequest(
                address = "dev@local.test",
                provider = Provider.DOVECOT,
                protocol = AuthenticationProtocol.IMAP,
            ),
        )

        assertEquals(emptyList(), response.correlatedLogs)
        assertEquals(4, logs.readCount)
        assertEquals(1, dovecot.probeRequests.size)
    }

    @Test
    fun generationCreatesRfcMessagesAndInjectsThemIntoTheRequestedProvider() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT)
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot),
            logSource = RecordingLogs(),
        )

        val response = backend.generateMessage(
            GenerateMessageRequest(
                targetAccount = "dev@local.test",
                provider = Provider.DOVECOT,
                sourceType = MessageSourceType.TEXT,
                content = "A body",
                subject = "A subject",
                count = 2,
            ),
        )

        assertEquals(listOf("message-1", "message-2"), response.messageIds)
        assertTrue(response.operation.success)
        assertEquals(2, dovecot.injectedMessages.size)
        assertTrue(dovecot.injectedMessages.all { "Subject: A subject" in it.rawEml })
    }

    @Test
    fun smtpGenerationUsesTheProvidersRealDeliveryPath() = runBlocking {
        val stalwart = RecordingProvider(Provider.STALWART)
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
        )

        val response = backend.generateMessage(
            GenerateMessageRequest(
                targetAccount = "dev@local.test",
                provider = Provider.STALWART,
                sourceType = MessageSourceType.RANDOM,
                deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
                seed = 42,
            ),
        )

        assertEquals(listOf("delivered-1"), response.messageIds)
        assertEquals("Delivered 1 message", response.operation.message)
        assertEquals(1, stalwart.deliveredMessages.size)
        assertTrue(stalwart.injectedMessages.isEmpty())
    }

    @Test
    fun dovecotAccountLogsCombineDovecotPostfixAndOAuthEvidence() = runBlocking {
        val logs = RecordingLogs()
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to RecordingProvider(Provider.DOVECOT)),
            logSource = logs,
        )

        assertEquals(
            listOf(
                "[dovecot] line-DOVECOT",
                "[postfix] line-POSTFIX",
                "[oauth2] line-OAUTH2",
            ),
            backend.accountLogs("dev@local.test", Provider.DOVECOT, null).lines,
        )
        assertEquals(
            listOf(
                LogRead(
                    LogService.DOVECOT,
                    DashboardLogAccount("dev@local.test"),
                    500,
                ),
                LogRead(
                    LogService.POSTFIX,
                    DashboardLogAccount("dev@local.test"),
                    500,
                ),
                LogRead(
                    LogService.OAUTH2,
                    DashboardLogAccount("dev@local.test"),
                    500,
                ),
            ),
            logs.requests,
        )
    }

    @Test
    fun dovecotAccountLogsRetainEvidenceFromEverySourceWhenOneSourceIsSaturated() = runBlocking {
        val logs = RecordingLogs(
            linesByService = mapOf(
                LogService.DOVECOT to listOf("dovecot-auth"),
                LogService.POSTFIX to listOf("postfix-delivery"),
                LogService.OAUTH2 to (1..500).map { index -> "oauth-$index" },
            ),
        )
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to RecordingProvider(Provider.DOVECOT)),
            logSource = logs,
        )

        val lines = backend.accountLogs("dev@local.test", Provider.DOVECOT, null).lines

        assertEquals(500, lines.size)
        assertTrue("[dovecot] dovecot-auth" in lines)
        assertTrue("[postfix] postfix-delivery" in lines)
        assertTrue(lines.any { it.startsWith("[oauth2] oauth-") })
    }

    @Test
    fun stalwartAccountLogsStayOnTheDedicatedStalwartChannel() = runBlocking {
        val logs = RecordingLogs()
        val stalwart = RecordingProvider(Provider.STALWART).apply {
            logAccount = DashboardLogAccount("dev@local.test", providerAccountId = "c")
        }
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.STALWART to stalwart),
            logSource = logs,
        )

        assertEquals(
            listOf("line-STALWART"),
            backend.accountLogs("dev@local.test", Provider.STALWART, "c").lines,
        )
        assertEquals(
            LogRead(
                LogService.STALWART,
                DashboardLogAccount("dev@local.test", providerAccountId = "c"),
                500,
            ),
            logs.requests.single(),
        )
    }
}

private class RecordingLogs(
    private val linesByService: Map<LogService, List<String>> = emptyMap(),
) : DashboardLogSource {
    val requests = mutableListOf<LogRead>()

    override fun read(
        service: LogService,
        account: DashboardLogAccount?,
        limit: Int,
    ): LogResponse {
        requests += LogRead(service, account, limit)
        return LogResponse(
            service,
            account?.address,
            linesByService[service] ?: listOf("line-${service.name}"),
        )
    }
}

private class SequencedProbeLogs(
    vararg snapshots: List<String>,
) : DashboardLogSource {
    private val snapshots = ArrayDeque(snapshots.toList())
    var readCount = 0

    override fun read(
        service: LogService,
        account: DashboardLogAccount?,
        limit: Int,
    ): LogResponse {
        readCount++
        val lines = snapshots.removeFirstOrNull() ?: error("Unexpected log poll")
        return LogResponse(service = service, account = account?.address, lines = lines)
    }
}

private data class LogRead(
    val service: LogService,
    val account: DashboardLogAccount?,
    val limit: Int,
)

private class RecordingProvider(
    override val provider: Provider,
) : LocalProviderOperations {
    val accounts = mutableListOf<AccountInfo>()
    val createdAccounts = mutableListOf<CreateAccountRequest>()
    val injectedMessages = mutableListOf<GeneratedMessage>()
    val deliveredMessages = mutableListOf<GeneratedMessage>()
    var logAccount = DashboardLogAccount("dev@local.test")
    var listFailure: RuntimeException? = null
    var statusFailure: RuntimeException? = null
    var status = ProviderStatus(provider, ProviderAvailability.READY)
    var beforeList: suspend () -> Unit = {}
    val probeRequests = mutableListOf<AuthenticationProbeRequest>()
    var probeResponse = "authentication failed"
    var probeSecrets = emptyList<String>()

    override suspend fun listAccounts(): List<AccountInfo> {
        beforeList()
        listFailure?.let { throw it }
        return accounts
    }

    override fun providerStatus(): ProviderStatus {
        statusFailure?.let { throw it }
        return status
    }

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo {
        createdAccounts += request
        return AccountInfo(
            address = request.address,
            provider = request.provider,
            protocols = request.protocols,
            credentialReadiness = CredentialReadiness.READY,
        )
    }

    override suspend fun dashboardLogAccount(
        address: String,
        providerAccountId: String?,
    ): DashboardLogAccount = logAccount

    override suspend fun deleteAccount(address: String, providerAccountId: String?) = Unit

    override suspend fun adoptPassword(
        address: String,
        request: AdoptPasswordRequest,
        providerAccountId: String?,
    ) = mail.sandbox.dashboard.contract.CredentialUpdateResponse(
        address,
        provider,
        CredentialReadiness.READY,
        OperationResponse(true, "verified"),
    )

    override suspend fun changePassword(
        address: String,
        newPassword: String,
        providerAccountId: String?,
    ) = mail.sandbox.dashboard.contract.CredentialUpdateResponse(
        address,
        provider,
        CredentialReadiness.READY,
        OperationResponse(true, "changed"),
    )

    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): LocalAuthenticationProbeResult {
        probeRequests += request
        return LocalAuthenticationProbeResult(
            response = AuthenticationProbeResponse(
                address = request.address,
                provider = request.provider,
                protocol = request.protocol,
                success = false,
                providerResponse = probeResponse,
                correlatedLogs = emptyList(),
            ),
            secretsToRedact = probeSecrets,
        )
    }

    override suspend fun listFolders(
        address: String,
        providerAccountId: String?,
    ): List<FolderInfo> = emptyList()

    override suspend fun createFolder(
        address: String,
        name: String,
        providerAccountId: String?,
    ): FolderInfo =
        FolderInfo(name, name, 0, 0)

    override suspend fun deleteFolder(
        address: String,
        folderId: String,
        providerAccountId: String?,
    ) = Unit

    override suspend fun listMessages(
        address: String,
        folderId: String?,
        providerAccountId: String?,
    ): List<MessageSummary> = emptyList()

    override suspend fun readMessage(
        address: String,
        messageId: String,
        folderId: String?,
        providerAccountId: String?,
    ): MessageDetail = error("not used")

    override suspend fun mutateMessages(
        address: String,
        request: MutateMessagesRequest,
    ): OperationResponse = OperationResponse(true, request.action.name)

    override suspend fun injectMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
        injectedMessages += messages
        return messages.indices.map { "message-${it + 1}" }
    }

    override suspend fun deliverMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
        deliveredMessages += messages
        return messages.indices.map { "delivered-${it + 1}" }
    }
}
