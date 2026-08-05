package mail.sandbox.dashboard.contract

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

class DashboardContractSerializationTest {
    private val json = Json

    @Test
    fun providerAndProtocolEnumsRoundTrip() {
        assertRoundTrip(Provider.DOVECOT)
        assertRoundTrip(Provider.STALWART)
        assertRoundTrip(MailProtocol.IMAP)
        assertRoundTrip(MailProtocol.POP3)
        assertRoundTrip(MailProtocol.JMAP)
        assertRoundTrip(MailProtocol.SMTP)
    }

    @Test
    fun accountContractsRoundTrip() {
        val account = AccountInfo(
            address = "dev@local.test",
            provider = Provider.STALWART,
            protocols = listOf(MailProtocol.IMAP, MailProtocol.JMAP, MailProtocol.SMTP),
            enabled = true,
        )

        assertRoundTrip(account)
        assertRoundTrip(
            CreateAccountRequest(
                address = account.address,
                password = "disposable-password",
                provider = account.provider,
                protocols = account.protocols,
            ),
        )
        assertRoundTrip(ChangePasswordRequest(newPassword = "replacement-password"))
        assertRoundTrip(AccountListResponse(accounts = listOf(account)))
    }

    @Test
    fun logContractsRoundTrip() {
        LogService.entries.forEach(::assertRoundTrip)
        assertEquals(
            "OAUTH2",
            json.decodeFromString<LogService>("\"OAUTH2\"").name,
        )
        assertRoundTrip(
            LogResponse(
                service = LogService.STALWART,
                account = "dev@local.test",
                lines = listOf("authenticated", "message delivered"),
            ),
        )
    }

    @Test
    fun folderContractsRoundTrip() {
        val folder = FolderInfo(
            id = "folder-1",
            name = "Inbox",
            totalMessages = 12,
            unreadMessages = 3,
        )

        assertRoundTrip(folder)
        assertRoundTrip(FolderListResponse(folders = listOf(folder)))
        assertRoundTrip(CreateFolderRequest(name = "Debug reproduction"))
    }

    @Test
    fun messageReadContractsRoundTrip() {
        val summary = MessageSummary(
            id = "message-1",
            folderId = "folder-1",
            mutationState = "email-state-7",
            subject = "Reproduction",
            fromAddress = "sender@local.test",
            receivedAt = "2026-08-05T12:00:00Z",
            isRead = false,
            isFlagged = true,
        )
        val detail = MessageDetail(
            id = summary.id,
            folderId = summary.folderId,
            mutationState = "email-state-8",
            subject = summary.subject,
            fromAddress = summary.fromAddress,
            toAddresses = listOf("dev@local.test"),
            sentAt = summary.receivedAt,
            textBody = "plain body",
            htmlBody = "<p>html body</p>",
            isRead = summary.isRead,
            isFlagged = summary.isFlagged,
        )

        assertRoundTrip(summary)
        assertRoundTrip(detail)
        assertRoundTrip(MessageListResponse(messages = listOf(summary)))
    }

    @Test
    fun messageGenerationContractsRoundTrip() {
        MessageSourceType.entries.forEach(::assertRoundTrip)
        MessageDeliveryMode.entries.forEach(::assertRoundTrip)
        val operation = OperationResponse(success = true, message = "generated")

        assertRoundTrip(
            GenerateMessageRequest(
                targetAccount = "dev@local.test",
                provider = Provider.DOVECOT,
                sourceType = MessageSourceType.RANDOM,
                deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
                content = null,
                subject = "Random fixture",
                seed = 42L,
                folderId = "Inbox",
                count = 3,
                fromAddress = "sender@local.test",
            ),
        )
        assertRoundTrip(
            GenerateMessageResponse(
                messageIds = listOf("message-1", "message-2", "message-3"),
                operation = operation,
            ),
        )
        assertRoundTrip(operation)
    }

    @Test
    fun messageMutationContractsRoundTrip() {
        MessageAction.entries.forEach(::assertRoundTrip)
        assertRoundTrip(
            MutateMessagesRequest(
                account = "dev@local.test",
                provider = Provider.STALWART,
                messageIds = listOf("message-1", "message-2"),
                mutationStates = mapOf(
                    "message-1" to "email-state-7",
                    "message-2" to "email-state-7",
                ),
                action = MessageAction.MOVE,
                destinationFolderId = "folder-2",
            ),
        )
    }

    private inline fun <reified T> assertRoundTrip(value: T) {
        assertEquals(value, json.decodeFromString<T>(json.encodeToString(value)))
    }
}
