package mail.sandbox.dashboard.server.acceptance

import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.http.encodeURLParameter
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AccountListResponse
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.ChangePasswordRequest
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.CredentialUpdateResponse
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.CreateFolderRequest
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.FolderListResponse
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.GenerateMessageResponse
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageListResponse
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.contract.Routes
import mail.sandbox.dashboard.server.api.DashboardApiError
import mail.sandbox.dashboard.server.api.dashboardApiRoutes
import mail.sandbox.dashboard.server.local.LocalDashboardBackend
import mail.sandbox.dashboard.server.gate.stalwart.GateCredential
import mail.sandbox.dashboard.server.gate.stalwart.GateJmapClient
import mail.sandbox.dashboard.server.gate.stalwart.GateJmapException
import mail.sandbox.dashboard.server.gate.stalwart.GateJmapFailure
import mail.sandbox.dashboard.server.gate.stalwart.KtorGateHttpTransport
import mail.sandbox.dashboard.server.provider.AccountCredentials
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationEndpoint
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationMechanism
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProbe
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProtocol
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationRequest

/**
 * Explicitly selected, destructive-to-generated-resources-only acceptance against the root stack.
 * [SingleStackAcceptanceEnvironment.load] is deliberately the first operation: direct selection
 * without the exact opt-in, checkout, endpoints, and runner-owned prefix is a hard failure.
 */
class SingleStackUsabilityLiveTest {
    @Test
    fun allRequestedOperationsAreUsableOnBothRootProviders() {
        val selected = SingleStackAcceptanceEnvironment.load()
        val baseline = selected.readSnapshot()
        val backend = LocalDashboardBackend.production(
            repositoryRoot = selected.repositoryRoot,
            environment = System.getenv(),
        )
        try {
            testApplication {
                application { routing { dashboardApiRoutes(backend) } }
                val api = LiveDashboardApi(client)
                api.assertRootLogsFunctional()
                val initial = api.listAccounts()
                assertEquals(
                    Provider.entries,
                    initial.providerStatuses.map { it.provider },
                )
                assertTrue(initial.providerStatuses.all {
                    it.availability == ProviderAvailability.READY
                })
                assertEquals(
                    baseline.providerAccounts,
                    initial.accounts.identities(),
                    "The live inventory must still contain every pre-acceptance provider identity",
                )

                api.runProviderWorkflow(selected, baseline, Provider.DOVECOT)
                api.runStalwartJmapOnlyWorkflow(selected, baseline)
                api.runStalwartSmtpOnlyWorkflow(selected, baseline)
                api.runProviderWorkflow(selected, baseline, Provider.STALWART)

                val finalInventory = api.listAccounts()
                selected.removeGeneratedCatalogIfInitiallyAbsent(baseline)
                selected.assertPreserved(baseline, finalInventory.accounts)
            }
        } finally {
            try {
                backend.close()
            } finally {
                selected.removeGeneratedCatalogIfInitiallyAbsent(baseline)
            }
        }
    }
}

internal suspend fun runAcceptanceCleanup(
    workflowFailure: Throwable?,
    cleanup: suspend () -> Unit,
) {
    withContext(NonCancellable) {
        try {
            cleanup()
        } catch (cleanupFailure: Throwable) {
            if (workflowFailure == null) throw cleanupFailure
            if (cleanupFailure !== workflowFailure) workflowFailure.addSuppressed(cleanupFailure)
        }
    }
}

private class LiveDashboardApi(
    private val client: HttpClient,
    private val deletedCredentialVerifier: DirectDeletedAccountCredentialVerifier =
        DirectDeletedAccountCredentialVerifier(),
) {
    suspend fun listAccounts(): AccountListResponse =
        client.get(Routes.ACCOUNTS).decode(HttpStatusCode.OK)

    suspend fun assertRootLogsFunctional() {
        val services = listOf(
            LogService.DOVECOT,
            LogService.POSTFIX,
            LogService.OAUTH2,
            LogService.STALWART,
        )
        val serviceLogs = services.associateWith { service ->
            client.get(
                "${Routes.LOGS}?service=${service.name}",
            ).decode<LogResponse>(HttpStatusCode.OK)
        }
        val allLogs = client.get(
            "${Routes.LOGS}?service=${LogService.ALL.name}",
        ).decode<LogResponse>(HttpStatusCode.OK)
        requireFunctionalGlobalLogs(allLogs, serviceLogs)
    }

    suspend fun runProviderWorkflow(
        environment: SingleStackAcceptanceEnvironment,
        baseline: SingleStackPreservationSnapshot,
        provider: Provider,
    ) {
        val address = environment.run.accountAddress(provider)
        val originalPassword = "${environment.run.prefix}-Password-1!"
        val changedPassword = "${environment.run.prefix}-Password-2!"
        val wrongPassword = "${environment.run.prefix}-Wrong-Password!"
        val protocols = provider.expectedProtocols()
        val before = listAccounts()
        assertEquals(baseline.providerAccounts, before.accounts.identities())

        var cleanupAccount: AccountInfo? = null
        var returnedProviderAccountId: String? = null
        val generatedFolders = linkedMapOf<String, FolderInfo>()
        var accountDeleted = false
        var workflowFailure: Throwable? = null
        try {
            val account = client.post(Routes.ACCOUNTS) {
                jsonBody(CreateAccountRequest(address, originalPassword, provider, protocols))
            }.decode<AccountInfo>(HttpStatusCode.Created)
            cleanupAccount = account
            returnedProviderAccountId = account.providerAccountId
            assertEquals(address, account.address)
            assertEquals(provider, account.provider)
            assertEquals(protocols, account.protocols)
            assertEquals(CredentialReadiness.READY, account.credentialReadiness)
            when (provider) {
                Provider.DOVECOT -> assertEquals(null, account.providerAccountId)
                Provider.STALWART -> assertFalse(account.providerAccountId.isNullOrBlank())
            }
            val providerAccountId = account.providerAccountId
            val afterCreate = listAccounts()
            assertTrue(afterCreate.accounts.any { it.sameIdentity(account) })
            assertTrue(
                baseline.providerAccounts.all { identity ->
                    afterCreate.accounts.any { it.sameIdentity(identity) }
                },
                "Creating an acceptance account must not hide pre-existing inventory",
            )

            val folderA = createFolder(
                account,
                environment.run.folderName("move-target"),
            ).also {
                environment.requireGeneratedFolder(it.name)
                generatedFolders[it.id] = it
            }
            val folderB = createFolder(
                account,
                environment.run.folderName("copy-target"),
            ).also {
                environment.requireGeneratedFolder(it.name)
                generatedFolders[it.id] = it
            }
            val folders = listFolders(account)
            assertTrue(folders.any { it.id == folderA.id && it.name == folderA.name })
            assertTrue(folders.any { it.id == folderB.id && it.name == folderB.name })

            val emlSubject = "${environment.run.prefix} EML"
            val emlBody = "Exact EML body for ${environment.run.prefix}."
            val eml = """
                From: acceptance-sender@local.test
                To: $address
                Date: Tue, 11 Aug 2026 12:00:00 +0000
                Subject: $emlSubject
                Message-ID: <${environment.run.prefix}-${provider.name.lowercase()}-eml@local.test>
                MIME-Version: 1.0
                Content-Type: text/plain; charset=UTF-8

                $emlBody
            """.trimIndent().replace("\n", "\r\n") + "\r\n"
            val emlId = generate(
                account,
                MessageSourceType.EML,
                MessageDeliveryMode.DIRECT_APPEND,
                content = eml,
                expectedMessageIdCount = 1,
            ).messageIds.single()

            val textSubject = "${environment.run.prefix} authored text"
            val textBody = "Authored acceptance body for $provider."
            val textId = generate(
                account,
                MessageSourceType.TEXT,
                MessageDeliveryMode.DIRECT_APPEND,
                content = textBody,
                subject = textSubject,
                expectedMessageIdCount = 1,
            ).messageIds.single()

            val randomSubject = "${environment.run.prefix} seeded random"
            val randomId = generate(
                account,
                MessageSourceType.RANDOM,
                MessageDeliveryMode.SMTP_DELIVERY,
                subject = randomSubject,
                seed = RANDOM_SEED,
                expectedMessageIdCount = 1,
            ).messageIds.single()

            val generatedMessageIds = setOf(emlId, textId, randomId)
            val generatedFolderMessages = listFolderMessages(account)
            val inbox = requireSingleFolderContainingMessageIds(
                generatedFolderMessages,
                generatedMessageIds,
            )
            val inboxMessages = generatedFolderMessages.single { (folder) ->
                folder.id == inbox.id
            }.second
            assertTrue(listOf(emlId, textId, randomId).all { generatedId ->
                inboxMessages.any { it.id == generatedId }
            })
            val emlDetail = readMessage(account, emlId, inbox.id)
            assertEquals(emlSubject, emlDetail.subject)
            assertTrue(emlBody in emlDetail.textBody.orEmpty())
            assertTrue(emlDetail.toAddresses.any { address in it })
            val textDetail = readMessage(account, textId, inbox.id)
            assertEquals(textSubject, textDetail.subject)
            assertTrue(textBody in textDetail.textBody.orEmpty())

            assertAuthenticationMatrix(
                account = account,
                rememberedPassword = originalPassword,
                wrongPassword = wrongPassword,
            )
            val oauthBearer = if (provider == Provider.DOVECOT) {
                "valid-$address".also { bearer ->
                    assertProbe(
                        account,
                        AuthenticationProtocol.OAUTH_IMAP,
                        credentialOverride = bearer,
                        expectedSuccess = true,
                    )
                }
            } else {
                null
            }
            val accountLogProbe = assertProbe(
                account,
                account.primaryAuthenticationProtocol(),
                credentialOverride = null,
                expectedSuccess = true,
            )
            val accountLogs = client.get(
                withProviderId(Routes.accountLogs(address, provider), providerAccountId),
            ).decode<LogResponse>(HttpStatusCode.OK)
            requireFunctionalAccountLogs(account, accountLogs, accountLogProbe)
            oauthBearer?.let { bearer ->
                val globalLogs = client.get(
                    "${Routes.LOGS}?service=${LogService.ALL.name}",
                ).decode<LogResponse>(HttpStatusCode.OK)
                requireFunctionalOAuthAccountLogs(
                    account = account,
                    accountLogs = accountLogs,
                    globalLogs = globalLogs,
                    submittedBearer = bearer,
                )
            }

            val adoption = client.post(
                withProviderId(
                    Routes.accountPasswordVerification(address, provider),
                    providerAccountId,
                ),
            ) {
                jsonBody(AdoptPasswordRequest(originalPassword))
            }.decode<CredentialUpdateResponse>(HttpStatusCode.OK)
            assertEquals(address, adoption.address)
            assertEquals(provider, adoption.provider)
            assertEquals(CredentialReadiness.READY, adoption.readiness)
            assertTrue(adoption.operation.success, adoption.operation.message)

            val passwordChange = client.put(
                withProviderId(Routes.accountPassword(address, provider), providerAccountId),
            ) {
                jsonBody(ChangePasswordRequest(changedPassword))
            }.decode<CredentialUpdateResponse>(HttpStatusCode.OK)
            assertTrue(passwordChange.operation.success, passwordChange.operation.message)
            assertEquals(CredentialReadiness.READY, passwordChange.readiness)
            assertProbe(
                account,
                account.primaryAuthenticationProtocol(),
                originalPassword,
                expectedSuccess = false,
            )
            assertProbe(account, account.primaryAuthenticationProtocol(), null, expectedSuccess = true)

            mutateAndRefresh(account, randomId, inbox.id, MessageAction.MARK_READ)
                .also { assertTrue(it.isRead) }
            mutateAndRefresh(account, randomId, inbox.id, MessageAction.MARK_UNREAD)
                .also { assertFalse(it.isRead) }
            mutateAndRefresh(account, randomId, inbox.id, MessageAction.FLAG)
                .also { assertTrue(it.isFlagged) }
            mutateAndRefresh(account, randomId, inbox.id, MessageAction.UNFLAG)
                .also { assertFalse(it.isFlagged) }

            mutate(account, randomId, inbox.id, MessageAction.MOVE, folderA.id)
            assertFalse(listMessages(account, inbox.id).any { it.id == randomId })
            val moved = listMessages(account, folderA.id).single { it.subject == randomSubject }
            mutate(account, moved.id, folderA.id, MessageAction.COPY, folderB.id)
            val copied = listMessages(account, folderB.id).single { it.subject == randomSubject }
            assertEquals(folderB.id, copied.folderId)
            val stillMoved = listMessages(account, folderA.id).single { it.subject == randomSubject }
            mutate(account, stillMoved.id, folderA.id, MessageAction.TRASH)
            assertFalse(listMessages(account, folderA.id).any { it.id == stillMoved.id })
            val (trashFolder, trashed) = requireUniqueMessageBySubject(
                listFolderMessages(account),
                randomSubject,
                excludedFolderIds = setOf(folderB.id),
            )
            mutate(account, trashed.id, trashFolder.id, MessageAction.DELETE)
            val copiedAfterPermanentDelete = listFolderMessages(account).flatMap { (folder, messages) ->
                messages.filter { it.subject == randomSubject }.map { folder to it }
            }
            assertTrue(copiedAfterPermanentDelete.all { (folder) -> folder.id == folderB.id })
            copiedAfterPermanentDelete.forEach { (folder, message) ->
                mutate(account, message.id, folder.id, MessageAction.DELETE)
            }
            assertTrue(
                listFolderMessages(account).all { (_, messages) ->
                    messages.none { it.subject == randomSubject }
                },
            )

            generatedFolders.values.toList().asReversed().forEach { folder ->
                deleteFolder(environment, account, folder, returnedProviderAccountId)
                generatedFolders.remove(folder.id)
            }

            deleteAccount(environment, account, returnedProviderAccountId)
            accountDeleted = true
            assertFalse(listAccounts().accounts.any { it.sameIdentity(account) })
            deletedCredentialVerifier.requireRejected(account, changedPassword)
            assertAuthenticationRemoved(account)
            val afterDelete = listAccounts()
            assertTrue(
                baseline.providerAccounts
                    .filter { it.provider != provider }
                    .all { identity -> afterDelete.accounts.any { it.sameIdentity(identity) } },
                "Deleting one provider's generated account must not affect the other provider",
            )
        } catch (failure: Throwable) {
            workflowFailure = failure
            throw failure
        } finally {
            runAcceptanceCleanup(workflowFailure) {
                cleanupProviderWorkflow(
                    environment = environment,
                    baseline = baseline,
                    provider = provider,
                    address = address,
                    capturedAccount = cleanupAccount,
                    generatedFolders = generatedFolders,
                    allowFolderCleanup = true,
                    alreadyDeleted = accountDeleted,
                )
            }
        }
    }

    suspend fun runStalwartJmapOnlyWorkflow(
        environment: SingleStackAcceptanceEnvironment,
        baseline: SingleStackPreservationSnapshot,
    ) {
        val profile = StalwartAcceptanceProfile.JMAP_ONLY
        val address = environment.run.accountAddress(profile)
        val originalPassword = "${environment.run.prefix}-Jmap-Only-1!"
        val changedPassword = "${environment.run.prefix}-Jmap-Only-2!"
        val wrongPassword = "${environment.run.prefix}-Jmap-Only-Wrong!"
        var created: AccountInfo? = null
        var returnedProviderAccountId: String? = null
        val generatedFolders = linkedMapOf<String, FolderInfo>()
        var accountDeleted = false
        var workflowFailure: Throwable? = null
        try {
            val decoded = createStalwartProfileAccount(address, originalPassword, profile)
            created = decoded
            returnedProviderAccountId = decoded.providerAccountId
            requireStalwartProfileAccount(decoded, address, profile)
            val account = refreshExactProfile(decoded, profile)
            assertBaselinePlusGenerated(baseline, account)

            assertProbe(account, AuthenticationProtocol.JMAP, null, expectedSuccess = true)
            assertDisabledProbe(account, AuthenticationProtocol.SMTP, "SMTP is not enabled")

            val folderA = createFolder(account, environment.run.folderName("jmap-only-move")).also {
                environment.requireGeneratedFolder(it.name)
                generatedFolders[it.id] = it
            }
            val folderB = createFolder(account, environment.run.folderName("jmap-only-copy")).also {
                environment.requireGeneratedFolder(it.name)
                generatedFolders[it.id] = it
            }
            val folders = listFolders(account)
            assertTrue(folders.any { it.id == folderA.id })
            assertTrue(folders.any { it.id == folderB.id })

            val subject = "${environment.run.prefix} JMAP-only direct append"
            val body = "JMAP-only acceptance body for ${environment.run.prefix}."
            val messageId = generate(
                account = account,
                source = MessageSourceType.TEXT,
                delivery = MessageDeliveryMode.DIRECT_APPEND,
                content = body,
                subject = subject,
                expectedMessageIdCount = 1,
            ).messageIds.single()
            assertGenerationBadRequest(
                account = account,
                source = MessageSourceType.RANDOM,
                delivery = MessageDeliveryMode.SMTP_DELIVERY,
                subject = "${environment.run.prefix} forbidden SMTP",
                expectedMessage = "SMTP is not enabled",
            )

            val inbox = requireSingleFolderContainingMessageIds(
                listFolderMessages(account),
                setOf(messageId),
            )
            val detail = readMessage(account, messageId, inbox.id)
            assertEquals(subject, detail.subject)
            assertTrue(body in detail.textBody.orEmpty())
            mutateAndRefresh(account, messageId, inbox.id, MessageAction.MARK_READ)
                .also { assertTrue(it.isRead) }
            mutateAndRefresh(account, messageId, inbox.id, MessageAction.MARK_UNREAD)
                .also { assertFalse(it.isRead) }
            mutateAndRefresh(account, messageId, inbox.id, MessageAction.FLAG)
                .also { assertTrue(it.isFlagged) }
            mutateAndRefresh(account, messageId, inbox.id, MessageAction.UNFLAG)
                .also { assertFalse(it.isFlagged) }
            mutate(account, messageId, inbox.id, MessageAction.MOVE, folderA.id)
            val moved = listMessages(account, folderA.id).single { it.subject == subject }
            mutate(account, moved.id, folderA.id, MessageAction.COPY, folderB.id)
            val copied = listMessages(account, folderB.id).single { it.subject == subject }
            mutate(account, copied.id, folderB.id, MessageAction.DELETE)
            val stillMoved = listMessages(account, folderA.id).single { it.subject == subject }
            mutate(account, stillMoved.id, folderA.id, MessageAction.TRASH)
            val (trash, trashed) = requireUniqueMessageBySubject(listFolderMessages(account), subject)
            mutate(account, trashed.id, trash.id, MessageAction.DELETE)

            changePassword(account, changedPassword)
            assertProbe(account, AuthenticationProtocol.JMAP, originalPassword, expectedSuccess = false)
            assertProbe(account, AuthenticationProtocol.JMAP, null, expectedSuccess = true)

            generatedFolders.values.toList().asReversed().forEach { folder ->
                deleteFolder(environment, account, folder, returnedProviderAccountId)
                generatedFolders.remove(folder.id)
            }
            deleteAccount(environment, account, returnedProviderAccountId)
            accountDeleted = true
            assertFalse(listAccounts().accounts.any { it.sameIdentity(account) })
            deletedCredentialVerifier.requireRejected(account, changedPassword)
            assertAuthenticationRemoved(account)
            assertBaselineRestored(environment, baseline)
        } catch (failure: Throwable) {
            workflowFailure = failure
            throw failure
        } finally {
            runAcceptanceCleanup(workflowFailure) {
                cleanupStalwartProfile(
                    environment = environment,
                    profile = profile,
                    address = address,
                    created = created,
                    generatedFolders = generatedFolders,
                    alreadyDeleted = accountDeleted,
                    baseline = baseline,
                )
            }
        }
    }

    suspend fun runStalwartSmtpOnlyWorkflow(
        environment: SingleStackAcceptanceEnvironment,
        baseline: SingleStackPreservationSnapshot,
    ) {
        val profile = StalwartAcceptanceProfile.SMTP_ONLY
        val address = environment.run.accountAddress(profile)
        val originalPassword = "${environment.run.prefix}-Smtp-Only-1!"
        val changedPassword = "${environment.run.prefix}-Smtp-Only-2!"
        var created: AccountInfo? = null
        var returnedProviderAccountId: String? = null
        var accountDeleted = false
        var workflowFailure: Throwable? = null
        try {
            val decoded = createStalwartProfileAccount(address, originalPassword, profile)
            created = decoded
            returnedProviderAccountId = decoded.providerAccountId
            requireStalwartProfileAccount(decoded, address, profile)
            val account = refreshExactProfile(decoded, profile)
            assertBaselinePlusGenerated(baseline, account)

            assertProbe(account, AuthenticationProtocol.SMTP, null, expectedSuccess = true)
            assertDisabledProbe(account, AuthenticationProtocol.JMAP, "JMAP is not enabled")
            assertMailboxBadRequest(account, "JMAP is not enabled")
            assertGenerationBadRequest(
                account = account,
                source = MessageSourceType.TEXT,
                delivery = MessageDeliveryMode.DIRECT_APPEND,
                content = "This append must be rejected.",
                subject = "${environment.run.prefix} forbidden JMAP append",
                expectedMessage = "JMAP is not enabled",
            )
            generate(
                account = account,
                source = MessageSourceType.RANDOM,
                delivery = MessageDeliveryMode.SMTP_DELIVERY,
                subject = "${environment.run.prefix} SMTP-only delivery",
                seed = RANDOM_SEED,
                expectedMessageIdCount = 0,
            )

            changePassword(account, changedPassword)
            assertProbe(account, AuthenticationProtocol.SMTP, originalPassword, expectedSuccess = false)
            assertProbe(account, AuthenticationProtocol.SMTP, null, expectedSuccess = true)

            deleteAccount(environment, account, returnedProviderAccountId)
            accountDeleted = true
            assertFalse(listAccounts().accounts.any { it.sameIdentity(account) })
            deletedCredentialVerifier.requireRejected(account, changedPassword)
            assertAuthenticationRemoved(account)
            assertBaselineRestored(environment, baseline)
        } catch (failure: Throwable) {
            workflowFailure = failure
            throw failure
        } finally {
            runAcceptanceCleanup(workflowFailure) {
                cleanupStalwartProfile(
                    environment = environment,
                    profile = profile,
                    address = address,
                    created = created,
                    generatedFolders = linkedMapOf(),
                    alreadyDeleted = accountDeleted,
                    baseline = baseline,
                )
            }
        }
    }

    private suspend fun createStalwartProfileAccount(
        address: String,
        password: String,
        profile: StalwartAcceptanceProfile,
    ): AccountInfo = client.post(Routes.ACCOUNTS) {
        jsonBody(
            CreateAccountRequest(
                address = address,
                password = password,
                provider = Provider.STALWART,
                protocols = profile.protocols,
            ),
        )
    }.decode(HttpStatusCode.Created)

    private fun requireStalwartProfileAccount(
        account: AccountInfo,
        address: String,
        profile: StalwartAcceptanceProfile,
    ) {
        assertEquals(address, account.address)
        assertEquals(Provider.STALWART, account.provider)
        assertEquals(profile.protocols, account.protocols)
        assertEquals(CredentialReadiness.READY, account.credentialReadiness)
        assertFalse(account.providerAccountId.isNullOrBlank())
    }

    private suspend fun refreshExactProfile(
        created: AccountInfo,
        profile: StalwartAcceptanceProfile,
    ): AccountInfo = listAccounts().accounts.single { candidate ->
        candidate.sameIdentity(created)
    }.also { refreshed ->
        assertEquals(profile.protocols, refreshed.protocols)
        assertEquals(CredentialReadiness.READY, refreshed.credentialReadiness)
    }

    private suspend fun assertBaselinePlusGenerated(
        baseline: SingleStackPreservationSnapshot,
        generated: AccountInfo,
    ) {
        val inventory = listAccounts().accounts
        assertTrue(inventory.any { it.sameIdentity(generated) })
        assertTrue(
            baseline.providerAccounts.all { identity ->
                inventory.any { it.sameIdentity(identity) }
            },
            "Profile creation must retain every pre-existing provider identity",
        )
    }

    private suspend fun assertBaselineRestored(
        environment: SingleStackAcceptanceEnvironment,
        baseline: SingleStackPreservationSnapshot,
    ) {
        val inventory = listAccounts()
        assertEquals(baseline.providerAccounts, inventory.accounts.identities())
        environment.removeGeneratedCatalogIfInitiallyAbsent(baseline)
        environment.assertPreserved(baseline, inventory.accounts)
    }

    private suspend fun assertDisabledProbe(
        account: AccountInfo,
        protocol: AuthenticationProtocol,
        expectedMessage: String,
    ) {
        val response = client.post(Routes.AUTHENTICATION_PROBES) {
            jsonBody(
                AuthenticationProbeRequest(
                    address = account.address,
                    provider = account.provider,
                    protocol = protocol,
                    providerAccountId = account.providerAccountId,
                ),
            )
        }
        response.requireProfileBadRequest(expectedMessage)
    }

    private suspend fun assertMailboxBadRequest(
        account: AccountInfo,
        expectedMessage: String,
    ) {
        val response = client.get(
            withProviderId(
                Routes.folders(account.address, account.provider),
                account.providerAccountId,
            ),
        )
        response.requireProfileBadRequest(expectedMessage)
    }

    private suspend fun assertGenerationBadRequest(
        account: AccountInfo,
        source: MessageSourceType,
        delivery: MessageDeliveryMode,
        content: String? = null,
        subject: String,
        expectedMessage: String,
    ) {
        val response = client.post(Routes.GENERATE_MESSAGE) {
            jsonBody(
                GenerateMessageRequest(
                    targetAccount = account.address,
                    provider = account.provider,
                    providerAccountId = account.providerAccountId,
                    sourceType = source,
                    deliveryMode = delivery,
                    content = content,
                    subject = subject,
                    seed = if (source == MessageSourceType.RANDOM) RANDOM_SEED else null,
                    fromAddress = "acceptance-sender@local.test",
                ),
            )
        }
        response.requireProfileBadRequest(expectedMessage)
    }

    private suspend fun changePassword(account: AccountInfo, newPassword: String) {
        val response = client.put(
            withProviderId(
                Routes.accountPassword(account.address, account.provider),
                account.providerAccountId,
            ),
        ) {
            jsonBody(ChangePasswordRequest(newPassword))
        }.decode<CredentialUpdateResponse>(HttpStatusCode.OK)
        assertTrue(response.operation.success, response.operation.message)
        assertEquals(CredentialReadiness.READY, response.readiness)
    }

    private suspend fun cleanupStalwartProfile(
        environment: SingleStackAcceptanceEnvironment,
        profile: StalwartAcceptanceProfile,
        address: String,
        created: AccountInfo?,
        generatedFolders: LinkedHashMap<String, FolderInfo>,
        alreadyDeleted: Boolean,
        baseline: SingleStackPreservationSnapshot,
    ) {
        require(address == environment.run.accountAddress(profile)) {
            "Stalwart profile cleanup address does not match its run-owned profile"
        }
        cleanupProviderWorkflow(
            environment = environment,
            baseline = baseline,
            provider = Provider.STALWART,
            address = address,
            capturedAccount = created,
            generatedFolders = generatedFolders,
            allowFolderCleanup = MailProtocol.JMAP in profile.protocols,
            alreadyDeleted = alreadyDeleted,
        )
    }

    private suspend fun cleanupProviderWorkflow(
        environment: SingleStackAcceptanceEnvironment,
        baseline: SingleStackPreservationSnapshot,
        provider: Provider,
        address: String,
        capturedAccount: AccountInfo?,
        generatedFolders: LinkedHashMap<String, FolderInfo>,
        allowFolderCleanup: Boolean,
        alreadyDeleted: Boolean,
    ) {
        var cleanupFailure: Throwable? = null
        var cleanupIdentity = recoverGeneratedAccountCleanupIdentity(
            run = environment.run,
            baseline = baseline.providerAccounts,
            provider = provider,
            address = address,
            inventory = listOfNotNull(capturedAccount),
        )
        val inventory = try {
            listAccounts().accounts
        } catch (failure: Throwable) {
            cleanupFailure = failure
            null
        }
        if (inventory != null) {
            try {
                cleanupIdentity = recoverGeneratedAccountCleanupIdentity(
                    run = environment.run,
                    baseline = baseline.providerAccounts,
                    provider = provider,
                    address = address,
                    inventory = inventory,
                )
            } catch (failure: Throwable) {
                cleanupIdentity = null
                cleanupFailure = cleanupFailure ?: failure
            }
        }
        var accountDeleted = alreadyDeleted
        if (cleanupIdentity != null && !accountDeleted) {
            val cleanupAccount = cleanupIdentity.account
            val immutableProviderAccountId = cleanupIdentity.providerAccountId
            if (allowFolderCleanup) {
                try {
                    listFolders(cleanupAccount).filter { environment.run.ownsName(it.name) }
                        .forEach { folder -> generatedFolders.putIfAbsent(folder.id, folder) }
                } catch (failure: Throwable) {
                    cleanupFailure = cleanupFailure ?: failure
                }
                generatedFolders.values.toList().asReversed().forEach { folder ->
                    try {
                        deleteFolder(
                            environment,
                            cleanupAccount,
                            folder,
                            immutableProviderAccountId,
                        )
                    } catch (failure: Throwable) {
                        cleanupFailure = cleanupFailure ?: failure
                    }
                }
            }
            try {
                deleteAccount(
                    environment,
                    cleanupAccount,
                    immutableProviderAccountId,
                )
                accountDeleted = true
            } catch (failure: Throwable) {
                cleanupFailure = cleanupFailure ?: failure
            }
        }
        if (provider == Provider.DOVECOT && accountDeleted) {
            try {
                environment.purgeGeneratedDovecotMaildir(address)
            } catch (failure: Throwable) {
                cleanupFailure = cleanupFailure ?: failure
            }
        }
        try {
            assertBaselineRestored(environment, baseline)
        } catch (failure: Throwable) {
            cleanupFailure = cleanupFailure ?: failure
        }
        cleanupFailure?.let { throw it }
    }

    private suspend fun assertAuthenticationMatrix(
        account: AccountInfo,
        rememberedPassword: String,
        wrongPassword: String,
    ) {
        account.authenticationProtocols().forEach { protocol ->
            val override = when (protocol) {
                AuthenticationProtocol.OAUTH_IMAP,
                AuthenticationProtocol.OAUTH_SMTP,
                -> "valid-${account.address}"
                else -> null
            }
            assertProbe(account, protocol, override, expectedSuccess = true)
        }
        val passwordFailure = assertProbe(
            account,
            account.primaryAuthenticationProtocol(),
            wrongPassword,
            expectedSuccess = false,
        )
        passwordFailure.assertSecretAbsent(wrongPassword)
        assertProbe(account, account.primaryAuthenticationProtocol(), null, expectedSuccess = true)

        if (account.provider == Provider.DOVECOT) {
            val wrongToken = "invalid-${account.address}"
            val oauthFailure = assertProbe(
                account,
                AuthenticationProtocol.OAUTH_IMAP,
                wrongToken,
                expectedSuccess = false,
            )
            oauthFailure.assertSecretAbsent(wrongToken)
            assertProbe(account, AuthenticationProtocol.IMAP, null, expectedSuccess = true)
        }
        assertTrue(rememberedPassword.isNotBlank())
    }

    private suspend fun assertProbe(
        account: AccountInfo,
        protocol: AuthenticationProtocol,
        credentialOverride: String?,
        expectedSuccess: Boolean,
    ): AuthenticationProbeResponse {
        val response = client.post(Routes.AUTHENTICATION_PROBES) {
            jsonBody(
                AuthenticationProbeRequest(
                    address = account.address,
                    provider = account.provider,
                    protocol = protocol,
                    credentialOverride = credentialOverride,
                    providerAccountId = account.providerAccountId,
                ),
            )
        }.decode<AuthenticationProbeResponse>(HttpStatusCode.OK)
        assertEquals(account.address, response.address)
        assertEquals(account.provider, response.provider)
        assertEquals(protocol, response.protocol)
        assertEquals(expectedSuccess, response.success, response.providerResponse)
        assertTrue(response.providerResponse.isNotBlank())
        assertTrue(response.correlatedLogs.isNotEmpty(), "Probe must return new root log lines")
        assertTrue(response.correlatedLogs.any { line ->
            account.address in line || account.providerAccountId?.let(line::contains) == true
        }, "Probe logs must remain correlated with the exact account identity")
        credentialOverride?.let(response::assertSecretAbsent)
        return response
    }

    private suspend fun assertAuthenticationRemoved(account: AccountInfo) {
        val response = client.post(Routes.AUTHENTICATION_PROBES) {
            jsonBody(
                AuthenticationProbeRequest(
                    address = account.address,
                    provider = account.provider,
                    protocol = account.primaryAuthenticationProtocol(),
                    credentialOverride = "deleted-account-proof",
                    providerAccountId = account.providerAccountId,
                ),
            )
        }
        assertEquals(HttpStatusCode.NotFound, response.status)
        val error = JSON.decodeFromString<DashboardApiError>(response.bodyAsText())
        assertEquals("not_found", error.error)
    }

    private suspend fun createFolder(account: AccountInfo, name: String): FolderInfo =
        client.post(withProviderId(Routes.folders(account.address, account.provider), account.providerAccountId)) {
            jsonBody(CreateFolderRequest(name))
        }.decode(HttpStatusCode.Created)

    private suspend fun deleteFolder(
        environment: SingleStackAcceptanceEnvironment,
        account: AccountInfo,
        folder: FolderInfo,
        returnedProviderAccountId: String?,
    ) {
        environment.requireGeneratedAccount(account, returnedProviderAccountId)
        environment.requireGeneratedFolder(folder.name)
        client.delete(
            withProviderId(
                Routes.folder(account.address, account.provider, folder.id),
                account.providerAccountId,
            ),
        ).decode<OperationResponse>(HttpStatusCode.OK).also { assertTrue(it.success, it.message) }
    }

    private suspend fun listFolders(account: AccountInfo): List<FolderInfo> =
        client.get(
            withProviderId(Routes.folders(account.address, account.provider), account.providerAccountId),
        ).decode<FolderListResponse>(HttpStatusCode.OK).folders

    private suspend fun generate(
        account: AccountInfo,
        source: MessageSourceType,
        delivery: MessageDeliveryMode,
        content: String? = null,
        subject: String? = null,
        seed: Long? = null,
        expectedMessageIdCount: Int = 1,
    ): GenerateMessageResponse = client.post(Routes.GENERATE_MESSAGE) {
        jsonBody(
            GenerateMessageRequest(
                targetAccount = account.address,
                provider = account.provider,
                providerAccountId = account.providerAccountId,
                sourceType = source,
                deliveryMode = delivery,
                content = content,
                subject = subject,
                seed = seed,
                fromAddress = "acceptance-sender@local.test",
            ),
        )
    }.decode<GenerateMessageResponse>(HttpStatusCode.Created).also {
        requireGeneratedMessageIds(it, expectedMessageIdCount)
    }

    private suspend fun listMessages(account: AccountInfo, folderId: String): List<MessageSummary> =
        client.get(
            withProviderId(
                Routes.messages(account.address, account.provider),
                account.providerAccountId,
                "folderId" to folderId,
            ),
        ).decode<MessageListResponse>(HttpStatusCode.OK).messages

    private suspend fun listFolderMessages(
        account: AccountInfo,
    ): List<Pair<FolderInfo, List<MessageSummary>>> = listFolders(account).map { folder ->
        folder to listMessages(account, folder.id)
    }

    private suspend fun readMessage(
        account: AccountInfo,
        messageId: String,
        folderId: String,
    ): MessageDetail = client.get(
        withProviderId(
            Routes.message(account.address, account.provider, messageId),
            account.providerAccountId,
            "folderId" to folderId,
        ),
    ).decode(HttpStatusCode.OK)

    private suspend fun mutateAndRefresh(
        account: AccountInfo,
        messageId: String,
        sourceFolderId: String,
        action: MessageAction,
    ): MessageSummary {
        mutate(account, messageId, sourceFolderId, action)
        return listMessages(account, sourceFolderId).single { it.id == messageId }
    }

    private suspend fun mutate(
        account: AccountInfo,
        messageId: String,
        sourceFolderId: String,
        action: MessageAction,
        destinationFolderId: String? = null,
    ) {
        val current = listMessages(account, sourceFolderId).single { it.id == messageId }
        val response = client.post(
            withProviderId(
                Routes.messageActions(account.address, account.provider),
                account.providerAccountId,
            ),
        ) {
            jsonBody(
                MutateMessagesRequest(
                    account = account.address,
                    provider = account.provider,
                    providerAccountId = account.providerAccountId,
                    messageIds = listOf(current.id),
                    mutationStates = mapOf(current.id to current.mutationState),
                    action = action,
                    sourceFolderId = sourceFolderId,
                    destinationFolderId = destinationFolderId,
                ),
            )
        }.decode<OperationResponse>(HttpStatusCode.OK)
        assertTrue(response.success, response.message)
    }

    private suspend fun deleteAccount(
        environment: SingleStackAcceptanceEnvironment,
        account: AccountInfo,
        returnedProviderAccountId: String?,
    ) {
        environment.requireGeneratedAccount(account, returnedProviderAccountId)
        client.delete(
            withProviderId(
                Routes.account(account.address, account.provider),
                account.providerAccountId,
            ),
        ).decode<OperationResponse>(HttpStatusCode.OK).also { assertTrue(it.success, it.message) }
    }
}

internal fun requireFunctionalGlobalLogs(
    allLogs: LogResponse,
    serviceLogs: Map<LogService, LogResponse>,
) {
    val expectedServices = listOf(
        LogService.DOVECOT,
        LogService.POSTFIX,
        LogService.OAUTH2,
        LogService.STALWART,
    )
    check(allLogs.service == LogService.ALL && allLogs.account == null) {
        "Global logs must identify the unscoped ALL service"
    }
    check(allLogs.lines.isNotEmpty()) { "Global ALL logs must contain provider output" }
    check(serviceLogs.keys == expectedServices.toSet()) {
        "Global log proof must include every root mail service exactly once"
    }
    expectedServices.forEach { service ->
        val response = requireNotNull(serviceLogs[service])
        check(response.service == service && response.account == null) {
            "Global ${service.name} logs returned inconsistent metadata"
        }
        check(response.lines.isNotEmpty()) {
            "Global ${service.name} logs must contain provider output"
        }
        val prefix = "[${service.name.lowercase()}] "
        check(allLogs.lines.any { combined ->
            combined.startsWith(prefix) && response.lines.any { line -> combined == prefix + line }
        }) {
            "Global ALL logs did not aggregate observable ${service.name} output"
        }
    }
}

internal fun requireFunctionalAccountLogs(
    account: AccountInfo,
    logs: LogResponse,
    probe: AuthenticationProbeResponse,
) {
    val expectedService = when (account.provider) {
        Provider.DOVECOT -> LogService.DOVECOT
        Provider.STALWART -> LogService.STALWART
    }
    check(logs.service == expectedService && logs.account == account.address) {
        "Account logs returned inconsistent provider identity"
    }
    check(
        probe.address == account.address &&
            probe.provider == account.provider &&
            probe.success &&
            probe.correlatedLogs.isNotEmpty(),
    ) {
        "Account log proof requires a successful, independently correlated authentication probe"
    }
    check(logs.lines.isNotEmpty()) { "Account logs must contain provider output" }
    check(logs.lines.any { accountLine ->
        probe.correlatedLogs.any { probeLine ->
            accountLine == probeLine || accountLine.endsWith(" $probeLine")
        }
    }) {
        "Account logs did not contain output observed from the exact account authentication probe"
    }
}

internal fun requireFunctionalOAuthAccountLogs(
    account: AccountInfo,
    accountLogs: LogResponse,
    globalLogs: LogResponse,
    submittedBearer: String,
) {
    check(account.provider == Provider.DOVECOT && submittedBearer.isNotBlank()) {
        "OAuth account log proof requires a Dovecot account and submitted bearer"
    }
    check(
        accountLogs.service == LogService.DOVECOT && accountLogs.account == account.address,
    ) { "OAuth account logs returned inconsistent provider identity" }
    check(globalLogs.service == LogService.ALL && globalLogs.account == null) {
        "OAuth global logs returned inconsistent metadata"
    }
    val expected = "Introspection identity=${account.address} outcome=active"
    val oauthPrefix = "[${LogService.OAUTH2.name.lowercase()}] "
    check(accountLogs.lines.any { line -> line.startsWith(oauthPrefix) && expected in line }) {
        "Account logs did not contain the successful OAuth introspection outcome"
    }
    check(globalLogs.lines.any { line -> line.startsWith(oauthPrefix) && expected in line }) {
        "Global logs did not contain the successful OAuth introspection outcome"
    }
    check(accountLogs.lines.none { submittedBearer in it }) {
        "Account logs exposed the submitted OAuth bearer"
    }
    check(globalLogs.lines.none { submittedBearer in it }) {
        "Global logs exposed the submitted OAuth bearer"
    }
}

internal class DirectDeletedAccountCredentialVerifier(
    private val probe: ProviderAuthenticationProbe = ProviderAuthenticationProbe(),
    internal val jmapRejectionProbe: suspend (AccountInfo, String) -> AuthenticationOutcome =
        ::probeDeletedJmapAccount,
) {
    suspend fun requireRejected(account: AccountInfo, formerPassword: String) {
        require(formerPassword.isNotBlank()) { "Former account password is absent" }
        if (
            account.provider == Provider.STALWART &&
            MailProtocol.JMAP in account.protocols &&
            MailProtocol.SMTP !in account.protocols
        ) {
            val outcome = jmapRejectionProbe(account, formerPassword)
            check(formerPassword !in outcome.diagnostic) {
                "Deleted account credential leaked into the provider diagnostic"
            }
            check(
                outcome is AuthenticationOutcome.MissingAccount ||
                    outcome is AuthenticationOutcome.WrongPassword,
            ) {
                "Provider-level JMAP credential rejection was not proven after deleting " +
                    "${account.address}: ${outcome.diagnostic}"
            }
            return
        }
        val request = when (account.provider) {
            Provider.DOVECOT -> ProviderAuthenticationRequest(
                protocol = ProviderAuthenticationProtocol.IMAP,
                mechanism = ProviderAuthenticationMechanism.PASSWORD,
                credentials = AccountCredentials(account.address, password = formerPassword),
            )
            Provider.STALWART -> ProviderAuthenticationRequest(
                protocol = ProviderAuthenticationProtocol.SMTP,
                mechanism = ProviderAuthenticationMechanism.PASSWORD,
                credentials = AccountCredentials(account.address, password = formerPassword),
                endpointOverride = ProviderAuthenticationEndpoint(
                    host = "127.0.0.1",
                    port = STALWART_SUBMISSION_PORT,
                    startTls = false,
                ),
            )
        }
        val outcome = probe.probe(request)
        check(formerPassword !in outcome.diagnostic) {
            "Deleted account credential leaked into the provider diagnostic"
        }
        val definitiveRejection = when (outcome) {
            is AuthenticationOutcome.MissingAccount -> true
            is AuthenticationOutcome.WrongPassword -> when (request.protocol) {
                ProviderAuthenticationProtocol.IMAP ->
                    outcome.diagnostic.contains(IMAP_AUTHENTICATION_FAILED, ignoreCase = true)
                ProviderAuthenticationProtocol.SMTP ->
                    SMTP_AUTHENTICATION_FAILED.containsMatchIn(outcome.diagnostic)
                ProviderAuthenticationProtocol.POP3 -> false
            }
            else -> false
        }
        check(definitiveRejection) {
            "Provider-level credential rejection was not proven after deleting " +
                "${account.provider.name} ${account.address}: ${outcome.diagnostic}"
        }
    }

    private companion object {
        const val STALWART_SUBMISSION_PORT = 8587
        const val IMAP_AUTHENTICATION_FAILED = "[AUTHENTICATIONFAILED]"
        val SMTP_AUTHENTICATION_FAILED = Regex("(?m)^\\s*535(?:[ -]|$)")
    }
}

private suspend fun probeDeletedJmapAccount(
    account: AccountInfo,
    formerPassword: String,
): AuthenticationOutcome {
    val password = formerPassword.toCharArray()
    val credential = try {
        GateCredential.basic(account.address, password)
    } finally {
        password.fill('\u0000')
    }
    return try {
        KtorGateHttpTransport().use { transport ->
            GateJmapClient(
                baseUrl = URI("http://127.0.0.1:8443"),
                credential = credential,
                transport = transport,
            ).use { client ->
                client.discoverSession()
                AuthenticationOutcome.Authenticated("JMAP authentication unexpectedly succeeded")
            }
        }
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (failure: GateJmapException) {
        when (val kind = failure.kind) {
            is GateJmapFailure.HttpStatus -> when (kind.status) {
                401, 403 -> AuthenticationOutcome.WrongPassword(
                    "JMAP authentication rejected ordinary credentials",
                )
                404 -> AuthenticationOutcome.MissingAccount("JMAP ordinary Account was not found")
                else -> AuthenticationOutcome.Unavailable(
                    "JMAP deletion probe failed with HTTP status ${kind.status}",
                )
            }
            GateJmapFailure.Transport,
            GateJmapFailure.InvalidResponse,
            is GateJmapFailure.MethodError,
            -> AuthenticationOutcome.Unavailable("JMAP deletion probe could not prove rejection")
        }
    }
}

private fun Provider.expectedProtocols(): List<MailProtocol> = when (this) {
    Provider.DOVECOT -> listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP)
    Provider.STALWART -> listOf(MailProtocol.JMAP, MailProtocol.SMTP)
}

internal fun AccountInfo.authenticationProtocols(): List<AuthenticationProtocol> = buildList {
    when (provider) {
        Provider.DOVECOT -> {
            if (MailProtocol.IMAP in protocols) add(AuthenticationProtocol.IMAP)
            if (MailProtocol.POP3 in protocols) add(AuthenticationProtocol.POP3)
            if (MailProtocol.SMTP in protocols) add(AuthenticationProtocol.SMTP)
            if (MailProtocol.IMAP in protocols) add(AuthenticationProtocol.OAUTH_IMAP)
            if (MailProtocol.SMTP in protocols) add(AuthenticationProtocol.OAUTH_SMTP)
        }
        Provider.STALWART -> {
            if (MailProtocol.JMAP in protocols) add(AuthenticationProtocol.JMAP)
            if (MailProtocol.SMTP in protocols) add(AuthenticationProtocol.SMTP)
        }
    }
}

internal fun AccountInfo.primaryAuthenticationProtocol(): AuthenticationProtocol =
    authenticationProtocols().firstOrNull {
        it != AuthenticationProtocol.OAUTH_IMAP && it != AuthenticationProtocol.OAUTH_SMTP
    } ?: error("Account has no enabled ordinary authentication protocol")

internal fun requireSingleFolderContainingMessageIds(
    folderMessages: List<Pair<FolderInfo, List<MessageSummary>>>,
    expectedMessageIds: Set<String>,
): FolderInfo {
    require(expectedMessageIds.isNotEmpty()) { "Generated message IDs are absent" }
    return folderMessages.single { (_, messages) ->
        messages.mapTo(hashSetOf(), MessageSummary::id).containsAll(expectedMessageIds)
    }.first
}

internal fun requireUniqueMessageBySubject(
    folderMessages: List<Pair<FolderInfo, List<MessageSummary>>>,
    subject: String,
    excludedFolderIds: Set<String> = emptySet(),
): Pair<FolderInfo, MessageSummary> = folderMessages
    .asSequence()
    .filterNot { (folder) -> folder.id in excludedFolderIds }
    .flatMap { (folder, messages) ->
        messages.asSequence().filter { it.subject == subject }.map { folder to it }
    }
    .single()

internal fun requireProfileBadRequest(
    error: DashboardApiError,
    expectedMessageFragment: String,
) {
    check(error.error == "bad_request") {
        "Disabled profile operation did not return bad_request"
    }
    check(expectedMessageFragment in error.message) {
        "Disabled profile operation did not report $expectedMessageFragment"
    }
}

internal fun requireGeneratedMessageIds(
    response: GenerateMessageResponse,
    expectedCount: Int,
): List<String> {
    require(expectedCount >= 0) { "Expected generated message ID count is invalid" }
    check(response.operation.success) { response.operation.message }
    check(response.messageIds.size == expectedCount) {
        "Generation returned ${response.messageIds.size} message IDs; expected $expectedCount"
    }
    return response.messageIds
}

private fun AccountInfo.sameIdentity(other: AccountInfo): Boolean =
    provider == other.provider &&
        address == other.address &&
        providerAccountId == other.providerAccountId

private fun AccountInfo.sameIdentity(other: ProviderIdentitySnapshot): Boolean =
    provider == other.provider &&
        address == other.address &&
        providerAccountId == other.providerAccountId

private fun List<AccountInfo>.identities(): List<ProviderIdentitySnapshot> = map { account ->
    ProviderIdentitySnapshot(account.provider, account.address, account.providerAccountId)
}.sortedWith(compareBy(ProviderIdentitySnapshot::provider, ProviderIdentitySnapshot::address))

private fun AuthenticationProbeResponse.assertSecretAbsent(secret: String) {
    assertFalse(secret in providerResponse)
    assertTrue(correlatedLogs.none { secret in it })
}

private fun withProviderId(
    route: String,
    providerAccountId: String?,
    vararg additional: Pair<String, String>,
): String {
    val parameters = buildList {
        providerAccountId?.let { add("providerAccountId" to it) }
        addAll(additional)
    }
    if (parameters.isEmpty()) return route
    return route + "?" + parameters.joinToString("&") { (name, value) ->
        "${name.encodeURLParameter()}=${value.encodeURLParameter()}"
    }
}

private suspend inline fun <reified T> HttpResponse.decode(expectedStatus: HttpStatusCode): T {
    val body = bodyAsText()
    assertEquals(expectedStatus, status, body)
    assertEquals(ContentType.Application.Json.contentType, contentType()?.contentType)
    return JSON.decodeFromString(body)
}

private suspend fun HttpResponse.requireProfileBadRequest(expectedMessageFragment: String) {
    val body = bodyAsText()
    assertEquals(HttpStatusCode.BadRequest, status, body)
    assertEquals(ContentType.Application.Json.contentType, contentType()?.contentType)
    requireProfileBadRequest(JSON.decodeFromString(body), expectedMessageFragment)
}

private inline fun <reified T> io.ktor.client.request.HttpRequestBuilder.jsonBody(value: T) {
    contentType(ContentType.Application.Json)
    setBody(JSON.encodeToString(value))
}

private val JSON = Json
private const val RANDOM_SEED = 8_110_2026L
