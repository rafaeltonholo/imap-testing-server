package mail.sandbox.dashboard.server.local

import java.net.URI
import kotlinx.coroutines.delay
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.AuthenticationProtocol
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
import mail.sandbox.dashboard.server.gate.stalwart.GateHttpTransport
import mail.sandbox.dashboard.server.gate.stalwart.KtorGateHttpTransport
import mail.sandbox.dashboard.server.provider.AccountCredentials
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationEndpoint
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationMechanism
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProbe
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProtocol
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationRequest
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartAccountCredentialCatalog
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartAccountLogin
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartCreateAccount
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartManagementCredentialProvider
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductAdapter
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductGateway
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductAccount
import mail.sandbox.dashboard.server.provider.stalwart.product.StalwartProductProtocol

internal fun interface StalwartSmtpAuthenticationProbe {
    fun probe(address: String, password: String): AuthenticationOutcome
}

internal class DefaultStalwartSmtpAuthenticationProbe(
    private val delegate: ProviderAuthenticationProbe = ProviderAuthenticationProbe(),
) : StalwartSmtpAuthenticationProbe {
    override fun probe(address: String, password: String): AuthenticationOutcome = delegate.probe(
        ProviderAuthenticationRequest(
            protocol = ProviderAuthenticationProtocol.SMTP,
            mechanism = ProviderAuthenticationMechanism.PASSWORD,
            credentials = AccountCredentials(address, password),
            endpointOverride = ProviderAuthenticationEndpoint(
                host = "127.0.0.1",
                port = 8587,
                startTls = false,
            ),
        ),
    )
}

internal class StalwartDashboardProvider(
    private val adapter: StalwartProductGateway,
    private val catalog: LocalAccountCatalog,
    private val smtpSender: LocalSmtpSender = LocalSmtpClient(
        LocalSmtpEndpoint.STALWART_SUBMISSION,
    ),
    private val smtpAuthenticationProbe: StalwartSmtpAuthenticationProbe =
        DefaultStalwartSmtpAuthenticationProbe(),
) : LocalProviderOperations, AutoCloseable {
    override val provider: Provider = Provider.STALWART

    override fun providerStatus(): ProviderStatus = ProviderStatus(
        provider = provider,
        availability = ProviderAvailability.READY,
    )

    override suspend fun listAccounts(): List<AccountInfo> {
        val accounts = adapter.listAccounts()
        return accounts.map { account ->
            val password = catalog.findByProviderAccountId(provider, account.id)?.password
            if (password == null) {
                accountInfo(account, CredentialReadiness.PASSWORD_REQUIRED)
            } else {
                val outcome = probeConfiguredLogin(account, password)
                val info = accountInfo(
                    account = account,
                    readiness = outcome.readiness(),
                    readinessMessage = safeDiagnostic(outcome.diagnostic, password),
                )
                if (outcome is AuthenticationOutcome.Authenticated) {
                    catalog.rememberVerifiedPassword(info, password)
                }
                info
            }
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
        val liveProtocols = account.protocols()
        catalog.put(
            candidate.copy(
                address = account.address,
                password = null,
                protocols = liveProtocols,
                providerAccountId = account.id,
            ),
        )
        val password = requireNotNull(candidate.password)
        val outcome = probeConfiguredLogin(account, password)
        val info = accountInfo(
            account = account,
            readiness = outcome.readiness(),
            readinessMessage = safeDiagnostic(outcome.diagnostic, password),
        )
        if (outcome is AuthenticationOutcome.Authenticated) {
            catalog.rememberVerifiedPassword(info, password)
        }
        return info
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
        adapter.deleteAccount(account.id)
        catalog.removeByProviderAccountId(provider, account.id)
    }

    override suspend fun adoptPassword(
        address: String,
        request: AdoptPasswordRequest,
        providerAccountId: String?,
    ): CredentialUpdateResponse {
        val account = account(address, providerAccountId)
        val outcome = probeConfiguredLogin(account, request.password)
        val successful = outcome is AuthenticationOutcome.Authenticated
        if (successful) {
            catalog.rememberVerifiedPassword(
                accountInfo(account, CredentialReadiness.READY),
                request.password,
            )
        }
        return credentialUpdate(
            account = account,
            outcome = outcome,
            successMessage = "Stalwart password verified through ordinary-account authentication",
            failurePrefix = "Stalwart password verification failed",
            secret = request.password,
        )
    }

    override suspend fun changePassword(
        address: String,
        newPassword: String,
        providerAccountId: String?,
    ): CredentialUpdateResponse {
        val account = account(address, providerAccountId)
        adapter.changePassword(account.id, newPassword)
        catalog.forgetPassword(accountInfo(account, CredentialReadiness.PASSWORD_REQUIRED))
        val outcome = probeConfiguredLogin(account, newPassword)
        val successful = outcome is AuthenticationOutcome.Authenticated
        if (successful) {
            catalog.rememberVerifiedPassword(
                accountInfo(account, CredentialReadiness.READY),
                newPassword,
            )
        }
        return credentialUpdate(
            account = account,
            outcome = outcome,
            successMessage =
                "Password changed on Stalwart and ordinary-account authentication succeeded",
            failurePrefix = "Stalwart changed the password but post-change authentication failed",
            secret = newPassword,
        )
    }

    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): LocalAuthenticationProbeResult {
        require(request.provider == provider) {
            "Authentication provider does not match Stalwart"
        }
        val account = account(request.address, request.providerAccountId)
        when (request.protocol) {
            AuthenticationProtocol.JMAP -> account.requireEnabled(StalwartProductProtocol.JMAP)
            AuthenticationProtocol.SMTP -> account.requireEnabled(StalwartProductProtocol.SMTP)
            AuthenticationProtocol.IMAP,
            AuthenticationProtocol.POP3,
            AuthenticationProtocol.OAUTH_IMAP,
            AuthenticationProtocol.OAUTH_SMTP,
            -> throw IllegalArgumentException(
                "Stalwart supports JMAP and SMTP password probes in this dashboard stack",
            )
        }
        val password = request.credentialOverride
            ?: catalog.findByProviderAccountId(provider, account.id)?.password
        val outcome = if (password == null) {
            AuthenticationOutcome.MissingCredentials("Credentials are required")
        } else {
            when (request.protocol) {
                AuthenticationProtocol.JMAP -> adapter.probeOrdinaryLogin(
                    account.id,
                    account.address,
                    password,
                )
                AuthenticationProtocol.SMTP -> smtpAuthenticationProbe.probe(
                    account.address,
                    password,
                )
                AuthenticationProtocol.IMAP,
                AuthenticationProtocol.POP3,
                AuthenticationProtocol.OAUTH_IMAP,
                AuthenticationProtocol.OAUTH_SMTP,
                -> throw IllegalArgumentException(
                    "Stalwart supports JMAP and SMTP password probes in this dashboard stack",
                )
            }
        }
        return LocalAuthenticationProbeResult(
            response = AuthenticationProbeResponse(
                address = account.address,
                provider = provider,
                protocol = request.protocol,
                success = outcome is AuthenticationOutcome.Authenticated,
                providerResponse = safeDiagnostic(outcome.diagnostic, password),
                correlatedLogs = emptyList(),
            ),
            secretsToRedact = listOfNotNull(password).filter(String::isNotEmpty),
        )
    }

    override suspend fun listFolders(
        address: String,
        providerAccountId: String?,
    ): List<FolderInfo> {
        val accountId = jmapMailAccount(address, providerAccountId).id
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
        val folder = adapter.createFolder(jmapMailAccount(address, providerAccountId).id, name)
        return FolderInfo(folder.id, folder.name, 0, 0)
    }

    override suspend fun deleteFolder(
        address: String,
        folderId: String,
        providerAccountId: String?,
    ) {
        adapter.deleteFolder(jmapMailAccount(address, providerAccountId).id, folderId)
    }

    override suspend fun listMessages(
        address: String,
        folderId: String?,
        providerAccountId: String?,
    ): List<MessageSummary> {
        val accountId = jmapMailAccount(address, providerAccountId).id
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
            jmapMailAccount(address, providerAccountId).id,
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
        val accountId = jmapMailAccount(address, request.providerAccountId).id
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
        val accountId = jmapMailAccount(request.targetAccount, request.providerAccountId).id
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
        val account = mailAccount(
            request.targetAccount,
            request.providerAccountId,
        )
        account.requireEnabled(StalwartProductProtocol.SMTP)
        val accountId = account.id
        val canonicalAddress = account.address
        val record = catalog.findByProviderAccountId(provider, accountId)
            ?: throw NoSuchElementException("Account is not registered in the dashboard")
        val credentials = LocalSmtpCredentials(
            canonicalAddress,
            requireNotNull(record.password) {
                "A verified Stalwart password is required for SMTP delivery"
            },
        )
        if (StalwartProductProtocol.JMAP !in account.enabledProtocols) {
            messages.forEach { message ->
                smtpSender.send(
                    envelopeFrom = canonicalAddress,
                    envelopeRecipient = canonicalAddress,
                    rawMessage = message.rawEml,
                    credentials = credentials,
                )
            }
            return emptyList()
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
                credentials = credentials,
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
    ): StalwartProductAccount {
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
        return account
    }

    private suspend fun mailAccount(
        address: String,
        expectedProviderAccountId: String?,
    ): StalwartProductAccount {
        val expectedId = expectedProviderAccountId
            ?: throw DashboardNotFoundException(
                "Stalwart provider Account ID is required; refresh the account list",
            )
        val login = catalog.findByProviderAccountId(provider, expectedId)
        if (login?.password == null) {
            throw IllegalStateException(
                "A verified password is required for Stalwart mail operations",
            )
        }
        return account(address, expectedId)
    }

    private suspend fun jmapMailAccount(
        address: String,
        expectedProviderAccountId: String?,
    ): StalwartProductAccount = mailAccount(address, expectedProviderAccountId).also { account ->
        account.requireEnabled(StalwartProductProtocol.JMAP)
    }

    private fun StalwartProductAccount.requireEnabled(protocol: StalwartProductProtocol) {
        require(protocol in enabledProtocols) {
            "${protocol.name} is not enabled for this Stalwart Account"
        }
    }

    private suspend fun probeConfiguredLogin(
        account: StalwartProductAccount,
        password: String,
    ): AuthenticationOutcome = when {
        StalwartProductProtocol.JMAP in account.enabledProtocols -> adapter.probeOrdinaryLogin(
            account.id,
            account.address,
            password,
        )
        StalwartProductProtocol.SMTP in account.enabledProtocols ->
            smtpAuthenticationProbe.probe(account.address, password)
        else -> AuthenticationOutcome.Unavailable(
            "Stalwart Account has no enabled authentication protocol",
        )
    }

    private fun accountInfo(
        account: StalwartProductAccount,
        readiness: CredentialReadiness,
        readinessMessage: String? = null,
    ): AccountInfo = AccountInfo(
        address = account.address,
        provider = provider,
        protocols = account.protocols(),
        credentialReadiness = readiness,
        providerAccountId = account.id,
        readinessMessage = readinessMessage,
    )

    private fun StalwartProductAccount.protocols(): List<MailProtocol> =
        enabledProtocols.mapNotNull { protocol ->
            when (protocol) {
                StalwartProductProtocol.JMAP -> MailProtocol.JMAP
                StalwartProductProtocol.SMTP -> MailProtocol.SMTP
                StalwartProductProtocol.IMAP -> null
            }
        }.sortedBy(MailProtocol::ordinal)

    private fun AuthenticationOutcome.readiness(): CredentialReadiness = when (this) {
        is AuthenticationOutcome.Authenticated -> CredentialReadiness.READY
        is AuthenticationOutcome.MissingCredentials -> CredentialReadiness.PASSWORD_REQUIRED
        is AuthenticationOutcome.WrongPassword,
        is AuthenticationOutcome.MissingAccount,
        -> CredentialReadiness.AUTHENTICATION_FAILED
        is AuthenticationOutcome.Unavailable,
        is AuthenticationOutcome.TimedOut,
        -> CredentialReadiness.PROVIDER_UNAVAILABLE
    }

    private fun credentialUpdate(
        account: StalwartProductAccount,
        outcome: AuthenticationOutcome,
        successMessage: String,
        failurePrefix: String,
        secret: String,
    ): CredentialUpdateResponse {
        val successful = outcome is AuthenticationOutcome.Authenticated
        val diagnostic = safeDiagnostic(outcome.diagnostic, secret)
        return CredentialUpdateResponse(
            address = account.address,
            provider = provider,
            readiness = outcome.readiness(),
            operation = OperationResponse(
                success = successful,
                message = if (successful) successMessage else "$failurePrefix: $diagnostic",
            ),
        )
    }

    private fun safeDiagnostic(value: String, secret: String?): String {
        val redacted = secret
            ?.takeIf(String::isNotEmpty)
            ?.let { value.replace(it, "[redacted]") }
            ?: value
        return redacted
            .map { character -> if (character.isISOControl()) ' ' else character }
            .joinToString("")
            .trim()
            .take(MAXIMUM_DIAGNOSTIC_CHARACTERS)
            .ifEmpty { "Stalwart authentication failed" }
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
        const val MAXIMUM_DIAGNOSTIC_CHARACTERS = 512
    }
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

internal object LocalStalwartManagementCredentialProvider :
    StalwartManagementCredentialProvider {
    override fun openCredential(): GateCredential = GateCredential.basic(
        MANAGEMENT_ADDRESS,
        MANAGEMENT_PASSWORD.toCharArray(),
    )

    private const val MANAGEMENT_ADDRESS = "dashboard-management@local.test"
    private const val MANAGEMENT_PASSWORD = "secret"
}

internal fun createStalwartDashboardProvider(
    catalog: LocalAccountCatalog,
    transport: GateHttpTransport = KtorGateHttpTransport(),
): StalwartDashboardProvider {
    val credentials = LocalStalwartCredentialCatalog(catalog)
    return StalwartDashboardProvider(
        adapter = StalwartProductAdapter(
            baseUri = URI("http://127.0.0.1:8443"),
            managementCredentialProvider = LocalStalwartManagementCredentialProvider,
            accountCredentialCatalog = credentials,
            transport = transport,
        ),
        catalog = catalog,
    )
}
