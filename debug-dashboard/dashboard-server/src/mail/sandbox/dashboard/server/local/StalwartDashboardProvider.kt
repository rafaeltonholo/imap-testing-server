package mail.sandbox.dashboard.server.local

import java.net.URI
import java.nio.file.Path
import kotlinx.coroutines.delay
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.CredentialUpdateResponse
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.contract.ProviderStatus
import mail.sandbox.dashboard.server.api.DashboardNotFoundException
import mail.sandbox.dashboard.server.gate.stalwart.GateCredential
import mail.sandbox.dashboard.server.gate.stalwart.StalwartGateSecretFiles
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartAccountCredentialCatalog
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartAccountLogin
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartCreateAccount
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartManagementCredentialProvider
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductAdapter
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductProtocol

internal class StalwartDashboardProvider(
    private val adapter: StalwartProductAdapter,
    private val catalog: LocalAccountCatalog,
    private val smtpSender: LocalSmtpSender = LocalSmtpClient(LocalSmtpEndpoint.STALWART),
) : LocalProviderOperations, AutoCloseable {
    override val provider: Provider = Provider.STALWART

    override fun providerStatus(): ProviderStatus = ProviderStatus(
        provider = provider,
        availability = ProviderAvailability.DEGRADED,
        message = TEMPORARY_UNAVAILABLE_MESSAGE,
    )

    override suspend fun listAccounts(): List<AccountInfo> {
        val accounts = adapter.listAccounts()
        return accounts.map { account ->
            AccountInfo(
                address = account.address,
                provider = provider,
                protocols = account.enabledProtocols.mapNotNull {
                    when (it) {
                        StalwartProductProtocol.JMAP -> MailProtocol.JMAP
                        StalwartProductProtocol.SMTP -> MailProtocol.SMTP
                        StalwartProductProtocol.IMAP -> null
                    }
                }.sortedBy(MailProtocol::ordinal),
                credentialReadiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
                providerAccountId = account.id,
                readinessMessage = TEMPORARY_UNAVAILABLE_MESSAGE,
            )
        }
    }

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo {
        require(request.provider == provider) { "Account provider does not match Stalwart" }
        val candidate = catalog.validated(
            LocalAccountRecord(
                provider = provider,
                address = request.address,
                password = request.password,
                protocols = request.protocols,
            ),
        )
        val protocols = productProtocols(candidate.protocols)
        val account = adapter.createAccount(
            StalwartCreateAccount(
                address = candidate.address,
                password = requireNotNull(candidate.password),
                enabledProtocols = protocols,
            ),
        )
        catalog.put(
            candidate.copy(
                address = account.address,
                password = null,
                protocols = account.enabledProtocols.mapNotNull { protocol ->
                    when (protocol) {
                        StalwartProductProtocol.JMAP -> MailProtocol.JMAP
                        StalwartProductProtocol.SMTP -> MailProtocol.SMTP
                        StalwartProductProtocol.IMAP -> null
                    }
                }.sortedBy(MailProtocol::ordinal),
                providerAccountId = account.id,
            ),
        )
        return AccountInfo(
            address = account.address,
            provider = provider,
            protocols = candidate.protocols,
            credentialReadiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
            providerAccountId = account.id,
            readinessMessage = TEMPORARY_UNAVAILABLE_MESSAGE,
        )
    }

    override suspend fun dashboardLogAccount(
        address: String,
        providerAccountId: String?,
    ): DashboardLogAccount {
        val (accountId, canonicalAddress) = account(address, providerAccountId)
        return DashboardLogAccount(canonicalAddress, providerAccountId = accountId)
    }

    override suspend fun deleteAccount(address: String, providerAccountId: String?) {
        val account = account(address, providerAccountId)
        adapter.deleteAccount(account.first)
        catalog.removeByProviderAccountId(provider, account.first)
    }

    override suspend fun adoptPassword(
        address: String,
        request: AdoptPasswordRequest,
        providerAccountId: String?,
    ): CredentialUpdateResponse {
        val account = account(address, providerAccountId)
        return unavailableCredentialUpdate(account.second, "verify")
    }

    override suspend fun changePassword(
        address: String,
        newPassword: String,
        providerAccountId: String?,
    ): CredentialUpdateResponse {
        val account = account(address, providerAccountId)
        return unavailableCredentialUpdate(account.second, "change")
    }

    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): LocalAuthenticationProbeResult {
        val account = account(request.address, request.providerAccountId)
        return LocalAuthenticationProbeResult(
            response = AuthenticationProbeResponse(
                address = account.second,
                provider = provider,
                protocol = request.protocol,
                success = false,
                providerResponse = TEMPORARY_UNAVAILABLE_MESSAGE,
                correlatedLogs = emptyList(),
            ),
        )
    }

    override suspend fun listFolders(
        address: String,
        providerAccountId: String?,
    ): List<FolderInfo> {
        val accountId = account(address, providerAccountId).first
        return adapter.listFolders(accountId).map { folder ->
            FolderInfo(
                id = folder.id,
                name = folder.name,
                totalMessages = folder.totalEmails,
                unreadMessages = folder.unreadEmails,
            )
        }
    }

    override suspend fun createFolder(
        address: String,
        name: String,
        providerAccountId: String?,
    ): FolderInfo {
        val folder = adapter.createFolder(account(address, providerAccountId).first, name)
        return FolderInfo(folder.id, folder.name, 0, 0)
    }

    override suspend fun deleteFolder(
        address: String,
        folderId: String,
        providerAccountId: String?,
    ) {
        adapter.deleteFolder(account(address, providerAccountId).first, folderId)
    }

    override suspend fun listMessages(
        address: String,
        folderId: String?,
        providerAccountId: String?,
    ): List<MessageSummary> {
        val accountId = account(address, providerAccountId).first
        return adapter.listMessages(accountId, folderId).map { message ->
            MessageSummary(
                id = message.id,
                folderId = folderId ?: message.mailboxIds.firstOrNull().orEmpty(),
                mutationState = message.state,
                subject = message.subject.ifBlank { null },
                fromAddress = message.sender,
                receivedAt = message.receivedAt,
                isRead = message.seen,
                isFlagged = message.flagged,
            )
        }
    }

    override suspend fun readMessage(
        address: String,
        messageId: String,
        folderId: String?,
        providerAccountId: String?,
    ): MessageDetail {
        val message = adapter.readMessage(
            account(address, providerAccountId).first,
            messageId,
        )
        return MessageDetail(
            id = message.summary.id,
            folderId = folderId ?: message.summary.mailboxIds.firstOrNull().orEmpty(),
            mutationState = message.summary.state,
            subject = message.summary.subject.ifBlank { null },
            fromAddress = message.summary.sender,
            toAddresses = message.recipients,
            sentAt = message.summary.receivedAt,
            textBody = message.textBody ?: message.summary.preview.ifBlank { null },
            htmlBody = message.htmlBody,
            isRead = message.summary.seen,
            isFlagged = message.summary.flagged,
        )
    }

    override suspend fun mutateMessages(
        address: String,
        request: MutateMessagesRequest,
    ): OperationResponse {
        val accountId = account(address, request.providerAccountId).first
        val expectedState = request.singleMutationState()
        when (request.action) {
            MessageAction.MARK_READ -> adapter.setSeen(
                accountId,
                request.messageIds,
                expectedState,
                true,
            )
            MessageAction.MARK_UNREAD -> adapter.setSeen(
                accountId,
                request.messageIds,
                expectedState,
                false,
            )
            MessageAction.FLAG -> adapter.setFlagged(
                accountId,
                request.messageIds,
                expectedState,
                true,
            )
            MessageAction.UNFLAG -> adapter.setFlagged(
                accountId,
                request.messageIds,
                expectedState,
                false,
            )
            MessageAction.MOVE -> adapter.moveMessages(
                accountId,
                request.messageIds,
                expectedState,
                requireNotNull(request.sourceFolderId),
                requireNotNull(request.destinationFolderId),
            )
            MessageAction.COPY -> adapter.copyMessages(
                accountId,
                request.messageIds,
                expectedState,
                requireNotNull(request.destinationFolderId),
            )
            MessageAction.TRASH -> adapter.trashMessages(
                accountId,
                request.messageIds,
                expectedState,
                requireNotNull(request.sourceFolderId),
            )
            MessageAction.DELETE -> adapter.deleteMessages(
                accountId,
                request.messageIds,
                expectedState,
            )
        }
        return OperationResponse(true, "Stalwart message operation completed")
    }

    private fun MutateMessagesRequest.singleMutationState(): String {
        require(messageIds.size == 1)
        require(messageIds.distinct().size == messageIds.size)
        require(mutationStates.keys == messageIds.toSet())
        return mutationStates.values.distinct().single()
    }

    override suspend fun injectMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
        val accountId = account(request.targetAccount, request.providerAccountId).first
        val mailboxId = request.folderId ?: adapter.listFolders(accountId)
            .firstOrNull { it.role == "inbox" }
            ?.id
            ?: throw DashboardNotFoundException("Stalwart Account has no Inbox mailbox")
        return messages.map { message ->
            adapter.importEml(accountId, mailboxId, message.rawEml).emailId
        }
    }

    override suspend fun deliverMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
        require(request.folderId == null) { "SMTP delivery always targets the Inbox" }
        val (accountId, canonicalAddress) = account(
            request.targetAccount,
            request.providerAccountId,
        )
        val record = catalog.findByProviderAccountId(provider, accountId)
            ?: throw NoSuchElementException("Account is not registered in the dashboard")
        require(MailProtocol.SMTP in record.protocols) {
            "SMTP is not enabled for this Stalwart Account"
        }
        val inbox = adapter.listFolders(accountId).firstOrNull { it.role == "inbox" }
            ?: throw DashboardNotFoundException("Stalwart Account has no Inbox mailbox")
        return messages.map { message ->
            val before = adapter.listMessages(accountId, inbox.id)
                .mapTo(hashSetOf()) { it.id }
            val expectedMessageId = messageIdentity(
                DovecotMimeParser.parse(message.rawEml).header("message-id"),
            )
            smtpSender.send(
                envelopeFrom = canonicalAddress,
                envelopeRecipient = canonicalAddress,
                rawMessage = message.rawEml,
                credentials = LocalSmtpCredentials(
                    canonicalAddress,
                    requireNotNull(record.password) {
                        "A verified Stalwart password is required for SMTP delivery"
                    },
                ),
            )
            repeat(MESSAGE_ARRIVAL_ATTEMPTS) { attempt ->
                val created = adapter.listMessages(accountId, inbox.id)
                    .filter { it.id !in before }
                val correlated = if (expectedMessageId == null) {
                    created.singleOrNull()
                } else {
                    created.firstOrNull { summary ->
                        summary.messageIds.any { value ->
                            messageIdentity(value) == expectedMessageId
                        }
                    }
                }
                if (correlated != null) return@map correlated.id
                if (attempt + 1 < MESSAGE_ARRIVAL_ATTEMPTS) {
                    delay(MESSAGE_ARRIVAL_DELAY_MILLIS)
                }
            }
            throw IllegalStateException("Could not identify the delivered Stalwart message")
        }
    }

    override fun close() {
        adapter.close()
    }

    private suspend fun account(
        address: String,
        expectedProviderAccountId: String?,
    ): Pair<String, String> {
        val expectedId = expectedProviderAccountId
            ?: throw DashboardNotFoundException(
                "Stalwart provider Account ID is required; refresh the account list",
            )
        val accounts = adapter.listAccounts()
        val account = accounts.firstOrNull {
            it.id == expectedId && it.address.equals(address, ignoreCase = true)
        } ?: throw DashboardNotFoundException(
            "Stalwart Account identity changed; refresh the account list",
        )
        return account.id to account.address
    }

    private fun productProtocols(protocols: List<MailProtocol>): Set<StalwartProductProtocol> {
        require(protocols.isNotEmpty() && protocols.all(ALLOWED_PROTOCOLS::contains)) {
            "Stalwart supports JMAP and SMTP in this dashboard stack"
        }
        return protocols.mapTo(linkedSetOf()) { protocol ->
            when (protocol) {
                MailProtocol.JMAP -> StalwartProductProtocol.JMAP
                MailProtocol.SMTP -> StalwartProductProtocol.SMTP
                else -> error("Protocol set was validated")
            }
        }
    }

    private companion object {
        val DEFAULT_PROTOCOLS = listOf(MailProtocol.JMAP, MailProtocol.SMTP)
        val ALLOWED_PROTOCOLS = DEFAULT_PROTOCOLS.toSet()
        const val MESSAGE_ARRIVAL_ATTEMPTS = 40
        const val MESSAGE_ARRIVAL_DELAY_MILLIS = 100L
        const val TEMPORARY_UNAVAILABLE_MESSAGE =
            "Stalwart ordinary authentication is unavailable until the normal provider adapter is active"
    }

    private fun unavailableCredentialUpdate(
        address: String,
        action: String,
    ): CredentialUpdateResponse = CredentialUpdateResponse(
        address = address,
        provider = provider,
        readiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
        operation = OperationResponse(
            success = false,
            message = "Stalwart password $action is unavailable: $TEMPORARY_UNAVAILABLE_MESSAGE",
        ),
    )
}

internal class LocalStalwartCredentialCatalog(
    private val catalog: LocalAccountCatalog,
) : StalwartAccountCredentialCatalog {
    override suspend fun find(accountId: String): StalwartAccountLogin? =
        catalog.findByProviderAccountId(Provider.STALWART, accountId)?.let { record ->
            record.password?.let { password ->
                StalwartAccountLogin(accountId, record.address, password)
            }
        }

    override suspend fun save(login: StalwartAccountLogin) {
        val existing = catalog.findByProviderAccountId(Provider.STALWART, login.accountId)
        catalog.put(
            LocalAccountRecord(
                provider = Provider.STALWART,
                address = login.address,
                password = login.password,
                protocols = existing?.protocols ?: listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                providerAccountId = login.accountId,
            ),
        )
    }

    override suspend fun remove(accountId: String) {
        catalog.removeByProviderAccountId(Provider.STALWART, accountId)
    }
}

internal class GateFixtureManagementCredentialProvider(
    private val dashboardRoot: Path,
    private val fixtureSecrets: Path,
) : StalwartManagementCredentialProvider {
    override fun openCredential(): GateCredential =
        readFixtureSecrets().use { secrets ->
            GateCredential.bearer(secrets.managementApiKey)
        }

    private fun readFixtureSecrets() = StalwartGateSecretFiles.readFixtureSecrets(
        projectRoot = dashboardRoot,
        environment = mapOf(
            "STALWART_GATE_FIXTURE_SECRETS_FILE" to fixtureSecrets.toString(),
        ),
    )
}

internal fun createStalwartDashboardProvider(
    repositoryRoot: Path,
    catalog: LocalAccountCatalog,
    environment: Map<String, String> = System.getenv(),
): StalwartDashboardProvider {
    val dashboardRoot = repositoryRoot.resolve("debug-dashboard").toAbsolutePath().normalize()
    val fixtureSecrets = Path.of(
        environment["DASHBOARD_STALWART_FIXTURE_SECRETS"]
            ?: dashboardRoot.resolve(".runtime/stalwart-gate0b/fixture-secrets").toString(),
    ).toAbsolutePath().normalize()
    val baseUri = URI(
        environment["DASHBOARD_STALWART_BASE_URL"] ?: "http://127.0.0.1:18443",
    )
    val credentials = LocalStalwartCredentialCatalog(catalog)
    return StalwartDashboardProvider(
        adapter = StalwartProductAdapter(
            baseUri = baseUri,
            managementCredentialProvider = GateFixtureManagementCredentialProvider(
                dashboardRoot,
                fixtureSecrets,
            ),
            accountCredentialCatalog = credentials,
        ),
        catalog = catalog,
    )
}
