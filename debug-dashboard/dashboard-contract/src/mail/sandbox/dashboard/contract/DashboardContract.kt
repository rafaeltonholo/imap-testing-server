package mail.sandbox.dashboard.contract

import kotlinx.serialization.Serializable

@Serializable
enum class Provider {
    DOVECOT,
    STALWART,
}

@Serializable
enum class MailProtocol {
    IMAP,
    POP3,
    JMAP,
    SMTP,
}

@Serializable
data class AccountInfo(
    val address: String,
    val provider: Provider,
    val protocols: List<MailProtocol>,
    val enabled: Boolean = true,
)

@Serializable
data class CreateAccountRequest(
    val address: String,
    val password: String,
    val provider: Provider,
    val protocols: List<MailProtocol>,
)

@Serializable
data class ChangePasswordRequest(val newPassword: String)

@Serializable
data class AccountListResponse(val accounts: List<AccountInfo>)

@Serializable
enum class LogService {
    ALL,
    DOVECOT,
    POSTFIX,
    OAUTH2,
    STALWART,
}

@Serializable
data class LogResponse(
    val service: LogService,
    val account: String? = null,
    val lines: List<String>,
)

@Serializable
data class FolderInfo(
    val id: String,
    val name: String,
    val totalMessages: Int,
    val unreadMessages: Int,
)

@Serializable
data class FolderListResponse(val folders: List<FolderInfo>)

@Serializable
data class CreateFolderRequest(val name: String)

@Serializable
data class MessageSummary(
    val id: String,
    val folderId: String,
    val mutationState: String,
    val subject: String?,
    val fromAddress: String?,
    val receivedAt: String?,
    val isRead: Boolean,
    val isFlagged: Boolean,
)

@Serializable
data class MessageDetail(
    val id: String,
    val folderId: String,
    val mutationState: String,
    val subject: String?,
    val fromAddress: String?,
    val toAddresses: List<String>,
    val sentAt: String?,
    val textBody: String?,
    val htmlBody: String?,
    val isRead: Boolean,
    val isFlagged: Boolean,
)

@Serializable
data class MessageListResponse(val messages: List<MessageSummary>)

@Serializable
enum class MessageSourceType {
    EML,
    TEXT,
    RANDOM,
}

@Serializable
enum class MessageDeliveryMode {
    DIRECT_APPEND,
    SMTP_DELIVERY,
}

@Serializable
data class GenerateMessageRequest(
    val targetAccount: String,
    val provider: Provider,
    val sourceType: MessageSourceType,
    val deliveryMode: MessageDeliveryMode = MessageDeliveryMode.DIRECT_APPEND,
    val content: String? = null,
    val subject: String? = null,
    val seed: Long? = null,
    val folderId: String? = null,
    val count: Int = 1,
    val fromAddress: String? = null,
)

@Serializable
data class GenerateMessageResponse(
    val messageIds: List<String>,
    val operation: OperationResponse,
)

@Serializable
enum class MessageAction {
    MARK_READ,
    MARK_UNREAD,
    FLAG,
    UNFLAG,
    MOVE,
    COPY,
    TRASH,
    DELETE,
}

@Serializable
data class MutateMessagesRequest(
    val account: String,
    val provider: Provider,
    val messageIds: List<String>,
    val mutationStates: Map<String, String>,
    val action: MessageAction,
    val sourceFolderId: String? = null,
    val destinationFolderId: String? = null,
)

@Serializable
data class OperationResponse(
    val success: Boolean,
    val message: String,
)
