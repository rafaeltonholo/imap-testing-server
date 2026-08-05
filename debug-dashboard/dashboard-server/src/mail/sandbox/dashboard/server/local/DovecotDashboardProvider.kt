package mail.sandbox.dashboard.server.local

import java.nio.charset.StandardCharsets
import kotlinx.coroutines.delay
import mail.sandbox.dashboard.contract.AccountInfo
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
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMailboxState
import mail.sandbox.dashboard.server.provider.dovecot.DovecotProductAdapter

internal class DovecotDashboardProvider(
    private val adapter: DovecotProductAdapter,
    private val catalog: LocalAccountCatalog,
    private val smtpSender: LocalSmtpSender = LocalSmtpClient(LocalSmtpEndpoint.POSTFIX),
) : LocalProviderOperations {
    override val provider: Provider = Provider.DOVECOT

    override suspend fun listAccounts(): List<AccountInfo> = adapter.listAccounts().map { account ->
        val record = catalog.find(provider, account.address)
        AccountInfo(
            address = account.address,
            provider = provider,
            protocols = record?.protocols ?: DEFAULT_PROTOCOLS,
        )
    }

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo {
        require(request.provider == provider) { "Account provider does not match Dovecot" }
        requireProtocols(request.protocols)
        val record = catalog.validated(
            LocalAccountRecord(
                provider = provider,
                address = request.address,
                password = request.password,
                protocols = request.protocols,
            ),
        )
        withPasswordBytes(record.password) { password ->
            adapter.createAccount(record.address, password)
        }
        catalog.put(record)
        return AccountInfo(record.address, provider, record.protocols)
    }

    override suspend fun dashboardLogAccount(address: String): DashboardLogAccount {
        val canonicalAddress = adapter.listAccounts()
            .firstOrNull { account -> account.address.equals(address, ignoreCase = true) }
            ?.address
            ?: throw DashboardNotFoundException("Dovecot Account was not found")
        return DashboardLogAccount(canonicalAddress)
    }

    override suspend fun deleteAccount(address: String) {
        adapter.deleteAccount(address)
        catalog.remove(provider, address)
    }

    override suspend fun changePassword(address: String, newPassword: String) {
        val existing = catalog.find(provider, address)
        val updated = catalog.validated(
            existing?.copy(password = newPassword) ?: LocalAccountRecord(
                provider = provider,
                address = address,
                password = newPassword,
                protocols = DEFAULT_PROTOCOLS,
            ),
        )
        withPasswordBytes(updated.password) { password ->
            adapter.changePassword(updated.address, password)
        }
        catalog.put(updated)
    }

    override suspend fun listFolders(address: String): List<FolderInfo> =
        adapter.listFolders(address).map { folder ->
            val messages = adapter.listMessages(address, folder.name)
            FolderInfo(
                id = folder.name,
                name = folder.name.removePrefix("INBOX.").ifBlank { "Inbox" },
                totalMessages = messages.size,
                unreadMessages = messages.count { "\\Seen" !in it.flags },
            )
        }

    override suspend fun createFolder(address: String, name: String): FolderInfo {
        val mailbox = mailbox(name)
        adapter.createFolder(address, mailbox)
        return FolderInfo(mailbox, mailbox.removePrefix("INBOX."), 0, 0)
    }

    override suspend fun deleteFolder(address: String, folderId: String) {
        adapter.deleteFolder(address, folderId)
    }

    override suspend fun listMessages(
        address: String,
        folderId: String?,
    ): List<MessageSummary> {
        val mailbox = folderId ?: "INBOX"
        return adapter.listMessages(address, mailbox).map { message ->
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
    ): MessageDetail {
        val mailbox = folderId ?: "INBOX"
        val uid = uid(messageId)
        val summary = adapter.listMessages(address, mailbox).firstOrNull { it.uid == uid }
            ?: throw DashboardNotFoundException("Dovecot message was not found")
        val raw = adapter.readRawMessage(address, mailbox, uid, summary.mailboxState)
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
        val source = requireNotNull(request.sourceFolderId) {
            "A source folder is required for Dovecot message operations"
        }
        val uids = request.messageIds.map(::uid)
        val expectedState = DovecotMailboxState.decode(request.singleMutationState())
        when (request.action) {
            MessageAction.MARK_READ -> adapter.markRead(address, source, uids, expectedState, true)
            MessageAction.MARK_UNREAD -> adapter.markRead(
                address,
                source,
                uids,
                expectedState,
                false,
            )
            MessageAction.FLAG -> adapter.setFlagged(address, source, uids, expectedState, true)
            MessageAction.UNFLAG -> adapter.setFlagged(address, source, uids, expectedState, false)
            MessageAction.MOVE -> adapter.moveMessages(
                address,
                source,
                uids,
                expectedState,
                requireNotNull(request.destinationFolderId),
            )
            MessageAction.COPY -> adapter.copyMessages(
                address,
                source,
                uids,
                expectedState,
                requireNotNull(request.destinationFolderId),
            )
            MessageAction.TRASH -> adapter.trashMessages(address, source, uids, expectedState)
            MessageAction.DELETE -> adapter.deleteMessages(address, source, uids, expectedState)
        }
        return OperationResponse(true, "Dovecot message operation completed")
    }

    override suspend fun injectMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
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
    ): List<String> = messages.map { message ->
        val before = adapter.listMessages(address, mailbox).mapTo(hashSetOf()) { it.uid }
        val expectedMessageId = messageIdentity(
            DovecotMimeParser.parse(message.rawEml).header("message-id"),
        )
        submit(message)
        repeat(MESSAGE_ARRIVAL_ATTEMPTS) { attempt ->
            val created = adapter.listMessages(address, mailbox).filter { it.uid !in before }
            val correlated = if (expectedMessageId == null) {
                created.singleOrNull()
            } else {
                created
                    .filter { messageIdentity(it.messageId) == expectedMessageId }
                    .maxByOrNull { it.uid }
            }
            if (correlated != null) return@map correlated.uid.toString()
            if (attempt + 1 < MESSAGE_ARRIVAL_ATTEMPTS) delay(MESSAGE_ARRIVAL_DELAY_MILLIS)
        }
        throw IllegalStateException("Could not identify the delivered Dovecot message")
    }

    private fun requireProtocols(protocols: List<MailProtocol>) {
        require(protocols.isNotEmpty() && protocols.all(ALLOWED_PROTOCOLS::contains)) {
            "Dovecot supports IMAP, POP3, and SMTP in this sandbox"
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
        require(messageIds.size == 1)
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
        const val MESSAGE_ARRIVAL_ATTEMPTS = 40
        const val MESSAGE_ARRIVAL_DELAY_MILLIS = 100L
    }
}

internal fun messageIdentity(value: String?): String? = value
    ?.trim()
    ?.removePrefix("<")
    ?.removeSuffix(">")
    ?.lowercase()
    ?.takeIf(String::isNotEmpty)
