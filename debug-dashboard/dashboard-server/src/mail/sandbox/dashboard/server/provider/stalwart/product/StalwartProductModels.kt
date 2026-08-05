package mail.sandbox.dashboard.server.provider.stalwart.product

internal enum class StalwartProductProtocol {
    IMAP,
    JMAP,
    SMTP,
}

internal data class StalwartProductAccount(
    val id: String,
    val address: String,
    val enabledProtocols: Set<StalwartProductProtocol>,
)

internal data class StalwartCreateAccount(
    val address: String,
    val password: String,
    val enabledProtocols: Set<StalwartProductProtocol>,
)

internal data class StalwartProductFolder(
    val id: String,
    val name: String,
    val role: String?,
    val parentId: String?,
    val totalEmails: Int,
    val unreadEmails: Int,
)

internal data class StalwartProductMessageSummary(
    val id: String,
    val state: String,
    val subject: String,
    val sender: String?,
    val receivedAt: String?,
    val preview: String,
    val mailboxIds: Set<String>,
    val seen: Boolean,
    val flagged: Boolean,
    val messageIds: List<String> = emptyList(),
)

internal data class StalwartProductMessage(
    val summary: StalwartProductMessageSummary,
    val recipients: List<String>,
    val textBody: String?,
    val htmlBody: String?,
)

internal data class StalwartImportedEmail(
    val emailId: String,
    val blobId: String,
)

internal class StalwartProductException(
    message: String,
) : IllegalStateException(message)
