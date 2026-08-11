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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
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
                api.assertRootLogsLoad()
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

                Provider.entries.forEach { provider ->
                    api.runProviderWorkflow(selected, baseline, provider)
                }

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

private class LiveDashboardApi(private val client: HttpClient) {
    suspend fun listAccounts(): AccountListResponse =
        client.get(Routes.ACCOUNTS).decode(HttpStatusCode.OK)

    suspend fun assertRootLogsLoad() {
        listOf(
            LogService.DOVECOT,
            LogService.POSTFIX,
            LogService.OAUTH2,
            LogService.STALWART,
        ).forEach { service ->
            val response = client.get(
                "${Routes.LOGS}?service=${service.name}",
            ).decode<LogResponse>(HttpStatusCode.OK)
            assertEquals(service, response.service)
            assertEquals(null, response.account)
        }
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
        val generatedFolders = linkedMapOf<String, FolderInfo>()
        var accountDeleted = false
        var workflowFailure: Throwable? = null
        try {
            val account = client.post(Routes.ACCOUNTS) {
                jsonBody(CreateAccountRequest(address, originalPassword, provider, protocols))
            }.decode<AccountInfo>(HttpStatusCode.Created)
            cleanupAccount = account
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

            val accountLogs = client.get(
                withProviderId(Routes.accountLogs(address, provider), providerAccountId),
            ).decode<LogResponse>(HttpStatusCode.OK)
            assertEquals(address, accountLogs.account)
            assertEquals(
                if (provider == Provider.DOVECOT) LogService.DOVECOT else LogService.STALWART,
                accountLogs.service,
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
            ).messageIds.single()

            val textSubject = "${environment.run.prefix} authored text"
            val textBody = "Authored acceptance body for $provider."
            val textId = generate(
                account,
                MessageSourceType.TEXT,
                MessageDeliveryMode.DIRECT_APPEND,
                content = textBody,
                subject = textSubject,
            ).messageIds.single()

            val randomSubject = "${environment.run.prefix} seeded random"
            val randomId = generate(
                account,
                MessageSourceType.RANDOM,
                MessageDeliveryMode.SMTP_DELIVERY,
                subject = randomSubject,
                seed = RANDOM_SEED,
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
            assertProbe(account, account.primaryProtocol(), originalPassword, expectedSuccess = false)
            assertProbe(account, account.primaryProtocol(), null, expectedSuccess = true)

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
                deleteFolder(environment, account, folder)
                generatedFolders.remove(folder.id)
            }

            deleteAccount(environment, account)
            accountDeleted = true
            assertFalse(listAccounts().accounts.any { it.sameIdentity(account) })
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
            var created = cleanupAccount
            var cleanupFailure: Throwable? = null
            if (created == null) {
                try {
                    created = listAccounts().accounts.singleOrNull { candidate ->
                        candidate.provider == provider && candidate.address == address
                    }
                } catch (failure: Throwable) {
                    cleanupFailure = cleanupFailure ?: failure
                }
            }
            if (created != null && !accountDeleted) {
                try {
                    listFolders(created).filter { folder ->
                        environment.run.ownsName(folder.name)
                    }.forEach { folder -> generatedFolders.putIfAbsent(folder.id, folder) }
                } catch (failure: Throwable) {
                    cleanupFailure = cleanupFailure ?: failure
                }
                generatedFolders.values.toList().asReversed().forEach { folder ->
                    try {
                        deleteFolder(environment, created, folder)
                    } catch (failure: Throwable) {
                        cleanupFailure = cleanupFailure ?: failure
                    }
                }
                try {
                    deleteAccount(environment, created)
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
            cleanupFailure?.let { cleanup ->
                if (workflowFailure == null) throw cleanup
                workflowFailure.addSuppressed(cleanup)
            }
        }
    }

    private suspend fun assertAuthenticationMatrix(
        account: AccountInfo,
        rememberedPassword: String,
        wrongPassword: String,
    ) {
        account.provider.authenticationProtocols().forEach { protocol ->
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
            account.primaryProtocol(),
            wrongPassword,
            expectedSuccess = false,
        )
        passwordFailure.assertSecretAbsent(wrongPassword)
        assertProbe(account, account.primaryProtocol(), null, expectedSuccess = true)

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
                    protocol = account.primaryProtocol(),
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
    ) {
        environment.requireGeneratedAccount(account)
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
        assertTrue(it.operation.success, it.operation.message)
        assertEquals(1, it.messageIds.size)
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
    ) {
        environment.requireGeneratedAccount(account)
        client.delete(
            withProviderId(
                Routes.account(account.address, account.provider),
                account.providerAccountId,
            ),
        ).decode<OperationResponse>(HttpStatusCode.OK).also { assertTrue(it.success, it.message) }
    }
}

private fun Provider.expectedProtocols(): List<MailProtocol> = when (this) {
    Provider.DOVECOT -> listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP)
    Provider.STALWART -> listOf(MailProtocol.JMAP, MailProtocol.SMTP)
}

private fun Provider.authenticationProtocols(): List<AuthenticationProtocol> = when (this) {
    Provider.DOVECOT -> listOf(
        AuthenticationProtocol.IMAP,
        AuthenticationProtocol.POP3,
        AuthenticationProtocol.SMTP,
        AuthenticationProtocol.OAUTH_IMAP,
        AuthenticationProtocol.OAUTH_SMTP,
    )
    Provider.STALWART -> listOf(AuthenticationProtocol.JMAP, AuthenticationProtocol.SMTP)
}

private fun AccountInfo.primaryProtocol(): AuthenticationProtocol = when (provider) {
    Provider.DOVECOT -> AuthenticationProtocol.IMAP
    Provider.STALWART -> AuthenticationProtocol.JMAP
}

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

private inline fun <reified T> io.ktor.client.request.HttpRequestBuilder.jsonBody(value: T) {
    contentType(ContentType.Application.Json)
    setBody(JSON.encodeToString(value))
}

private val JSON = Json
private const val RANDOM_SEED = 8_110_2026L
