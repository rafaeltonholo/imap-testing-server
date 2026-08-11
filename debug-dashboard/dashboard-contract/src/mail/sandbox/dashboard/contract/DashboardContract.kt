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
enum class CredentialReadiness {
    READY,
    PASSWORD_REQUIRED,
    AUTHENTICATION_FAILED,
    PROVIDER_UNAVAILABLE,
}

@Serializable
enum class ProviderAvailability {
    READY,
    DEGRADED,
    UNAVAILABLE,
    UPGRADE_REQUIRED,
}

@Serializable
data class ProviderStatus(
    val provider: Provider,
    val availability: ProviderAvailability,
    val message: String? = null,
)

@Serializable
enum class AuthenticationProtocol {
    IMAP,
    POP3,
    SMTP,
    JMAP,
    OAUTH_IMAP,
    OAUTH_SMTP,
}

@Serializable
data class AccountInfo(
    val address: String,
    val provider: Provider,
    val protocols: List<MailProtocol>,
    val credentialReadiness: CredentialReadiness,
    val providerAccountId: String? = null,
    val readinessMessage: String? = null,
    val stale: Boolean = false,
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
data class AdoptPasswordRequest(val password: String)

@Serializable
data class CredentialUpdateResponse(
    val address: String,
    val provider: Provider,
    val readiness: CredentialReadiness,
    val operation: OperationResponse,
)

fun CredentialUpdateResponse.requireAchievedOperation(): CredentialUpdateResponse = also {
    check(operation.success) { operation.message }
}

@Serializable
data class AuthenticationProbeRequest(
    val address: String,
    val provider: Provider,
    val protocol: AuthenticationProtocol,
    val credentialOverride: String? = null,
    val providerAccountId: String? = null,
)

@Serializable
data class AuthenticationProbeResponse(
    val address: String,
    val provider: Provider,
    val protocol: AuthenticationProtocol,
    val success: Boolean,
    val providerResponse: String,
    val correlatedLogs: List<String>,
)

@Serializable
data class AccountListResponse(
    val accounts: List<AccountInfo>,
    val providerStatuses: List<ProviderStatus>,
) {
    init {
        require(providerStatuses.map(ProviderStatus::provider) == Provider.entries) {
            "Provider statuses must contain DOVECOT and STALWART exactly once in that order"
        }
    }
}

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
    val providerAccountId: String? = null,
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
    val providerAccountId: String? = null,
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
