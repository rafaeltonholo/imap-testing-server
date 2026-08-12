package mail.sandbox.dashboard.server.local

import java.nio.charset.StandardCharsets
import kotlinx.coroutines.CancellationException
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
import mail.sandbox.dashboard.server.api.DashboardBadRequestException
import mail.sandbox.dashboard.server.api.DashboardNotFoundException
import mail.sandbox.dashboard.server.provider.AccountCredentials
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationMechanism
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProbe
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProtocol
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationRequest
import mail.sandbox.dashboard.server.provider.dovecot.DovecotImapClient
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMailboxClient
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMailboxState
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMessageCommand
import mail.sandbox.dashboard.server.provider.dovecot.DovecotProductAdapter

internal class DovecotDashboardProvider(
    private val adapter: DovecotProductAdapter,
    private val catalog: LocalAccountCatalog,
    private val mailboxClient: DovecotMailboxClient = DovecotImapClient(
        accountExists = DovecotAccountExistence(adapter)::contains,
    ),
    private val smtpSender: LocalSmtpSender = LocalSmtpClient(
        LocalSmtpEndpoint.POSTFIX_DELIVERY,
    ),
    private val authenticationProbe: ProviderAuthenticationProbe = ProviderAuthenticationProbe(),
) : LocalProviderOperations {
    override val provider: Provider = Provider.DOVECOT

    override suspend fun listAccounts(): List<AccountInfo> {
        var unavailableDiagnostic: String? = null
        return adapter.listAccounts().map { account ->
            unavailableDiagnostic?.let { diagnostic ->
                return@map accountInfo(
                    address = account.address,
                    readiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
                    readinessMessage =
                        "Authentication probe skipped after Dovecot became unavailable: $diagnostic",
                )
            }
            val plainPassword = adapter.plainPassword(account.address)
            val password = if (plainPassword != null) {
                plainPassword
            } else {
                try {
                    catalog.find(provider, account.address)?.password
                } catch (cancellation: CancellationException) {
                    throw cancellation
                } catch (_: Exception) {
                    return@map accountInfo(
                        address = account.address,
                        readiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
                        readinessMessage =
                            "Dashboard credential catalog is unavailable for this account",
                    )
                }
            }
            if (password == null) {
                accountInfo(
                    address = account.address,
                    readiness = CredentialReadiness.PASSWORD_REQUIRED,
                )
            } else {
                val outcome = mailboxClient.probe(AccountCredentials(account.address, password))
                if (
                    outcome is AuthenticationOutcome.Unavailable ||
                    outcome is AuthenticationOutcome.TimedOut
                ) {
                    unavailableDiagnostic = outcome.diagnostic
                }
                accountInfo(
                    address = account.address,
                    readiness = outcome.readiness(),
                    readinessMessage = outcome.diagnostic,
                )
            }
        }
    }

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo {
        require(request.provider == provider) { "Account provider does not match Dovecot" }
        requireProtocols(request.protocols)
        val record = catalog.validated(
            LocalAccountRecord(
                provider = provider,
                address = request.address,
                password = request.password,
                protocols = DEFAULT_PROTOCOLS,
            ),
        )
        val password = requireNotNull(record.password)
        withPasswordBytes(password) { passwordBytes ->
            adapter.createAccount(record.address, passwordBytes)
        }
        return try {
            val credentials = AccountCredentials(record.address, password)
            requireAuthenticated(mailboxClient.probe(credentials))
            val existingFolders = mailboxClient.listFolders(credentials)
                .mapTo(hashSetOf()) { folder -> folder.name }
            DEFAULT_CREATED_FOLDERS.filterNot(existingFolders::contains).forEach { folder ->
                mailboxClient.createFolder(credentials, folder)
            }
            catalog.put(record)
            accountInfo(record.address, CredentialReadiness.READY)
        } catch (failure: Throwable) {
            try {
                adapter.deleteAccount(record.address)
            } catch (rollbackFailure: Throwable) {
                if (rollbackFailure !== failure) failure.addSuppressed(rollbackFailure)
            }
            try {
                catalog.remove(provider, record.address)
            } catch (cleanupFailure: Throwable) {
                if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
            }
            throw failure
        }
    }

    override suspend fun dashboardLogAccount(
        address: String,
        providerAccountId: String?,
    ): DashboardLogAccount {
        requireDovecotIdentity(providerAccountId)
        val canonicalAddress = adapter.listAccounts()
            .firstOrNull { account -> account.address.equals(address, ignoreCase = true) }
            ?.address
            ?: throw DashboardNotFoundException("Dovecot Account was not found")
        return DashboardLogAccount(canonicalAddress)
    }

    override suspend fun deleteAccount(address: String, providerAccountId: String?) {
        requireDovecotIdentity(providerAccountId)
        adapter.deleteAccount(address)
        catalog.remove(provider, address)
    }

    override suspend fun adoptPassword(
        address: String,
        request: AdoptPasswordRequest,
        providerAccountId: String?,
    ): CredentialUpdateResponse {
        requireDovecotIdentity(providerAccountId)
        val canonical = liveAddress(address)
        val outcome = mailboxClient.probe(AccountCredentials(canonical, request.password))
        val readiness = outcome.readiness()
        val successful = outcome is AuthenticationOutcome.Authenticated
        if (successful) {
            catalog.rememberVerifiedPassword(
                accountInfo(canonical, CredentialReadiness.READY),
                request.password,
            )
        }
        return credentialUpdate(
            address = canonical,
            readiness = readiness,
            success = successful,
            message = if (successful) {
                "Dovecot password verified"
            } else {
                "Dovecot password verification failed: ${outcome.diagnostic}"
            },
        )
    }

    override suspend fun changePassword(
        address: String,
        newPassword: String,
        providerAccountId: String?,
    ): CredentialUpdateResponse {
        requireDovecotIdentity(providerAccountId)
        val canonical = liveAddress(address)
        val existing = catalog.find(provider, canonical)
        val updated = catalog.validated(
            existing?.copy(password = newPassword, protocols = DEFAULT_PROTOCOLS)
                ?: LocalAccountRecord(
                provider = provider,
                address = canonical,
                password = newPassword,
                protocols = DEFAULT_PROTOCOLS,
            ),
        )
        withPasswordBytes(requireNotNull(updated.password)) { password ->
            adapter.changePassword(updated.address, password)
        }
        val outcome = mailboxClient.probe(
            AccountCredentials(updated.address, requireNotNull(updated.password)),
        )
        val readiness = outcome.readiness()
        val successful = outcome is AuthenticationOutcome.Authenticated
        if (successful) {
            catalog.rememberVerifiedPassword(
                accountInfo(updated.address, CredentialReadiness.READY),
                requireNotNull(updated.password),
            )
        }
        return credentialUpdate(
            address = updated.address,
            readiness = readiness,
            success = successful,
            message = if (successful) {
                "Password changed on Dovecot and ordinary authentication succeeded"
            } else {
                "Dovecot changed the password but post-change authentication failed: " +
                    outcome.diagnostic
            },
        )
    }

    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): LocalAuthenticationProbeResult {
        require(request.provider == provider) { "Authentication provider does not match Dovecot" }
        requireDovecotIdentity(request.providerAccountId)
        val canonical = liveAddress(request.address)
        val protocol = when (request.protocol) {
            AuthenticationProtocol.IMAP,
            AuthenticationProtocol.OAUTH_IMAP,
            -> ProviderAuthenticationProtocol.IMAP
            AuthenticationProtocol.POP3 -> ProviderAuthenticationProtocol.POP3
            AuthenticationProtocol.SMTP,
            AuthenticationProtocol.OAUTH_SMTP,
            -> ProviderAuthenticationProtocol.SMTP
            AuthenticationProtocol.JMAP -> throw IllegalArgumentException(
                "Dovecot JMAP authentication probes are not supported",
            )
        }
        val mechanism = when (request.protocol) {
            AuthenticationProtocol.OAUTH_IMAP,
            AuthenticationProtocol.OAUTH_SMTP,
            -> ProviderAuthenticationMechanism.OAUTHBEARER
            else -> ProviderAuthenticationMechanism.PASSWORD
        }
        val probeSecret = if (mechanism == ProviderAuthenticationMechanism.PASSWORD) {
            request.credentialOverride ?: rememberedPassword(canonical)
        } else {
            request.credentialOverride
        }
        val credentials = if (mechanism == ProviderAuthenticationMechanism.PASSWORD) {
            AccountCredentials(
                address = canonical,
                password = probeSecret,
            )
        } else {
            AccountCredentials(
                address = canonical,
                tokenOverride = probeSecret,
            )
        }
        val outcome = authenticationProbe.probe(
            ProviderAuthenticationRequest(protocol, mechanism, credentials),
        )
        return LocalAuthenticationProbeResult(
            response = AuthenticationProbeResponse(
                address = canonical,
                provider = provider,
                protocol = request.protocol,
                success = outcome is AuthenticationOutcome.Authenticated,
                providerResponse = outcome.diagnostic,
                correlatedLogs = emptyList(),
            ),
            secretsToRedact = listOfNotNull(probeSecret).filter(String::isNotEmpty),
        )
    }

    override suspend fun listFolders(
        address: String,
        providerAccountId: String?,
    ): List<FolderInfo> {
        requireDovecotIdentity(providerAccountId)
        val credentials = credentials(address)
        return mailboxClient.listFolders(credentials).map { folder ->
            val messages = mailboxClient.listMessages(credentials, folder.name)
            FolderInfo(
                id = folder.name,
                name = folder.name.removePrefix("INBOX.").ifBlank { "Inbox" },
                totalMessages = messages.size,
                unreadMessages = messages.count { "\\Seen" !in it.flags },
            )
        }
    }

    override suspend fun createFolder(
        address: String,
        name: String,
        providerAccountId: String?,
    ): FolderInfo {
        requireDovecotIdentity(providerAccountId)
        val mailbox = mailbox(name)
        mailboxClient.createFolder(credentials(address), mailbox)
        return FolderInfo(mailbox, mailbox.removePrefix("INBOX."), 0, 0)
    }

    override suspend fun deleteFolder(
        address: String,
        folderId: String,
        providerAccountId: String?,
    ) {
        requireDovecotIdentity(providerAccountId)
        mailboxClient.deleteFolder(credentials(address), folderId)
    }

    override suspend fun listMessages(
        address: String,
        folderId: String?,
        providerAccountId: String?,
    ): List<MessageSummary> {
        requireDovecotIdentity(providerAccountId)
        val mailbox = folderId ?: "INBOX"
        return mailboxClient.listMessages(credentials(address), mailbox).map { message ->
            MessageSummary(
                id = message.uid.toString(),
                folderId = mailbox,
                mutationState = message.mailboxState.encode(),
                subject = message.subject.ifBlank { null },
                fromAddress = message.from.ifBlank { null },
                receivedAt = message.date.ifBlank { null },
                isRead = "\\Seen" in message.flags,
                isFlagged = "\\Flagged" in message.flags,
            )
        }
    }

    override suspend fun readMessage(
        address: String,
        messageId: String,
        folderId: String?,
        providerAccountId: String?,
    ): MessageDetail {
        requireDovecotIdentity(providerAccountId)
        val mailbox = folderId ?: "INBOX"
        val uid = uid(messageId)
        val credentials = credentials(address)
        val summary = mailboxClient.listMessages(credentials, mailbox).firstOrNull { it.uid == uid }
            ?: throw DashboardNotFoundException("Dovecot message was not found")
        val raw = mailboxClient.readMessage(
            credentials,
            mailbox,
            uid,
            summary.mailboxState,
        )
        val parsed = parseEml(raw)
        return MessageDetail(
            id = messageId,
            folderId = mailbox,
            mutationState = summary.mailboxState.encode(),
            subject = parsed.header("subject") ?: summary.subject.ifBlank { null },
            fromAddress = parsed.header("from") ?: summary.from.ifBlank { null },
            toAddresses = parsed.header("to")
                ?.split(',')
                ?.map(String::trim)
                ?.filter(String::isNotEmpty)
                .orEmpty(),
            sentAt = parsed.header("date") ?: summary.date.ifBlank { null },
            textBody = parsed.textBody,
            htmlBody = parsed.htmlBody,
            isRead = "\\Seen" in summary.flags,
            isFlagged = "\\Flagged" in summary.flags,
        )
    }

    override suspend fun mutateMessages(
        address: String,
        request: MutateMessagesRequest,
    ): OperationResponse {
        requireDovecotIdentity(request.providerAccountId)
        val source = requireNotNull(request.sourceFolderId) {
            "A source folder is required for Dovecot message operations"
        }
        val uids = request.messageIds.map(::uid)
        val expectedState = DovecotMailboxState.decode(request.singleMutationState())
        val command = when (request.action) {
            MessageAction.MARK_READ ->
                DovecotMessageCommand.MarkRead(source, uids, expectedState, read = true)
            MessageAction.MARK_UNREAD ->
                DovecotMessageCommand.MarkRead(source, uids, expectedState, read = false)
            MessageAction.FLAG ->
                DovecotMessageCommand.SetFlagged(source, uids, expectedState, flagged = true)
            MessageAction.UNFLAG ->
                DovecotMessageCommand.SetFlagged(source, uids, expectedState, flagged = false)
            MessageAction.MOVE -> DovecotMessageCommand.Move(
                source,
                uids,
                expectedState,
                requireNotNull(request.destinationFolderId),
            )
            MessageAction.COPY -> DovecotMessageCommand.Copy(
                source,
                uids,
                expectedState,
                requireNotNull(request.destinationFolderId),
            )
            MessageAction.TRASH -> DovecotMessageCommand.Trash(source, uids, expectedState)
            MessageAction.DELETE -> DovecotMessageCommand.Delete(source, uids, expectedState)
        }
        mailboxClient.mutate(credentials(address), command)
        return OperationResponse(true, "Dovecot message operation completed")
    }

    override suspend fun injectMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
        requireDovecotIdentity(request.providerAccountId)
        val mailbox = request.folderId ?: "INBOX"
        return captureMessages(request.targetAccount, mailbox, messages) { message ->
            adapter.saveRawEmail(
                request.targetAccount,
                mailbox,
                message.rawEml.toByteArray(StandardCharsets.UTF_8),
            )
        }
    }

    override suspend fun deliverMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
        requireDovecotIdentity(request.providerAccountId)
        require(request.folderId == null) { "SMTP delivery always targets the Inbox" }
        val account = listAccounts().firstOrNull { it.address == request.targetAccount }
            ?: throw DashboardNotFoundException("Dovecot Account was not found")
        require(MailProtocol.SMTP in account.protocols) {
            "SMTP is not enabled for this Dovecot Account"
        }
        return captureMessages(request.targetAccount, "INBOX", messages) { message ->
            smtpSender.send(
                envelopeFrom = request.targetAccount,
                envelopeRecipient = request.targetAccount,
                rawMessage = message.rawEml,
                credentials = null,
            )
        }
    }

    private suspend fun captureMessages(
        address: String,
        mailbox: String,
        messages: List<GeneratedMessage>,
        submit: (GeneratedMessage) -> Unit,
    ): List<String> {
        val credentials = credentials(address)
        return messages.map { message ->
            val before = mailboxClient.listMessages(credentials, mailbox)
                .mapTo(hashSetOf()) { it.uid }
            val expectedMessageId = messageIdentity(
                DovecotMimeParser.parse(message.rawEml).header("message-id"),
            )
            submit(message)
            repeat(MESSAGE_ARRIVAL_ATTEMPTS) { attempt ->
                val created = mailboxClient.listMessages(credentials, mailbox)
                    .filter { it.uid !in before }
                val correlated = if (expectedMessageId == null) {
                    created.singleOrNull()
                } else {
                    created
                        .filter { messageIdentity(it.messageId) == expectedMessageId }
                        .maxByOrNull { it.uid }
                }
                if (correlated != null) return@map correlated.uid.toString()
                if (attempt + 1 < MESSAGE_ARRIVAL_ATTEMPTS) {
                    delay(MESSAGE_ARRIVAL_DELAY_MILLIS)
                }
            }
            throw IllegalStateException("Could not identify the delivered Dovecot message")
        }
    }

    private fun requireProtocols(protocols: List<MailProtocol>) {
        require(protocols.size == DEFAULT_PROTOCOLS.size && protocols.toSet() == ALLOWED_PROTOCOLS) {
            "Dovecot accounts always support exactly IMAP, POP3, and SMTP in this sandbox"
        }
    }

    private fun requireDovecotIdentity(providerAccountId: String?) {
        require(providerAccountId == null) {
            "Dovecot accounts do not use a provider Account ID"
        }
    }

    private fun credentials(address: String): AccountCredentials {
        val canonical = liveAddress(address)
        val password = rememberedPassword(canonical)
            ?: throw IllegalStateException("Dovecot account password is not available")
        return AccountCredentials(canonical, password)
    }

    private fun liveAddress(address: String): String = adapter.listAccounts()
        .firstOrNull { candidate -> candidate.address.equals(address, ignoreCase = true) }
        ?.address
        ?: throw DashboardNotFoundException("Dovecot Account was not found")

    private fun rememberedPassword(address: String): String? =
        adapter.plainPassword(address) ?: catalog.find(provider, address)?.password

    private fun accountInfo(
        address: String,
        readiness: CredentialReadiness,
        readinessMessage: String? = null,
    ): AccountInfo = AccountInfo(
        address = address,
        provider = provider,
        protocols = DEFAULT_PROTOCOLS,
        credentialReadiness = readiness,
        providerAccountId = null,
        readinessMessage = readinessMessage,
    )

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
        address: String,
        readiness: CredentialReadiness,
        success: Boolean,
        message: String,
    ): CredentialUpdateResponse = CredentialUpdateResponse(
        address = address,
        provider = provider,
        readiness = readiness,
        operation = OperationResponse(success = success, message = message),
    )

    private fun requireAuthenticated(outcome: AuthenticationOutcome) {
        if (outcome !is AuthenticationOutcome.Authenticated) {
            throw IllegalStateException(
                "Ordinary Dovecot authentication failed: ${outcome.diagnostic}",
            )
        }
    }

    private fun mailbox(name: String): String {
        val trimmed = name.trim()
        if (trimmed == "INBOX" || trimmed.startsWith("INBOX.")) return trimmed
        return "INBOX.$trimmed"
    }

    private fun uid(value: String): Long = value.toLongOrNull()?.takeIf { it > 0 }
        ?: throw DashboardBadRequestException("Dovecot message ID is invalid")

    private fun MutateMessagesRequest.singleMutationState(): String {
        require(messageIds.isNotEmpty())
        require(messageIds.distinct().size == messageIds.size)
        require(mutationStates.keys == messageIds.toSet())
        return mutationStates.values.distinct().single()
    }

    private inline fun <T> withPasswordBytes(password: String, block: (ByteArray) -> T): T {
        val bytes = password.toByteArray(StandardCharsets.UTF_8)
        return try {
            block(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun parseEml(raw: String): DovecotParsedMessage = DovecotMimeParser.parse(raw)

    private companion object {
        val DEFAULT_PROTOCOLS = listOf(
            MailProtocol.IMAP,
            MailProtocol.POP3,
            MailProtocol.SMTP,
        )
        val ALLOWED_PROTOCOLS = DEFAULT_PROTOCOLS.toSet()
        val DEFAULT_CREATED_FOLDERS = listOf(
            "INBOX.Drafts",
            "INBOX.Sent",
            "INBOX.Trash",
        )
        const val MESSAGE_ARRIVAL_ATTEMPTS = 40
        const val MESSAGE_ARRIVAL_DELAY_MILLIS = 100L
    }
}

internal class DovecotAccountExistence(
    private val adapter: DovecotProductAdapter,
) {
    fun contains(address: String): Boolean =
        adapter.listAccounts().any { account -> account.address == address }
}

internal fun messageIdentity(value: String?): String? = value
    ?.trim()
    ?.removePrefix("<")
    ?.removeSuffix(">")
    ?.lowercase()
    ?.takeIf(String::isNotEmpty)
