package mail.sandbox.dashboard.contract

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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
        CredentialReadiness.entries.forEach(::assertRoundTrip)
        ProviderAvailability.entries.forEach(::assertRoundTrip)
        AuthenticationProtocol.entries.forEach(::assertRoundTrip)
    }

    @Test
    fun accountContractsRoundTrip() {
        val account = AccountInfo(
            address = "dev@local.test",
            provider = Provider.STALWART,
            protocols = listOf(MailProtocol.IMAP, MailProtocol.JMAP, MailProtocol.SMTP),
            providerAccountId = "account-42",
            credentialReadiness = CredentialReadiness.AUTHENTICATION_FAILED,
            readinessMessage = "Remembered password was rejected",
            stale = true,
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
        assertRoundTrip(AdoptPasswordRequest(password = "existing-password"))
        assertRoundTrip(ChangePasswordRequest(newPassword = "replacement-password"))
        assertRoundTrip(
            CredentialUpdateResponse(
                address = account.address,
                provider = account.provider,
                readiness = CredentialReadiness.READY,
                operation = OperationResponse(success = true, message = "Password verified"),
            ),
        )
        assertRoundTrip(
            AccountListResponse(
                accounts = listOf(account),
                providerStatuses = providerStatuses(),
            ),
        )
    }

    @Test
    fun credentialUpdateRequiresAnAchievedProviderOperation() {
        val rejected = CredentialUpdateResponse(
            address = "dev@local.test",
            provider = Provider.DOVECOT,
            readiness = CredentialReadiness.AUTHENTICATION_FAILED,
            operation = OperationResponse(false, "password rejected"),
        )
        val achieved = rejected.copy(
            readiness = CredentialReadiness.READY,
            operation = OperationResponse(true, "password changed"),
        )

        assertEquals(achieved, achieved.requireAchievedOperation())
        assertEquals(
            "password rejected",
            assertFailsWith<IllegalStateException> {
                rejected.requireAchievedOperation()
            }.message,
        )
    }

    @Test
    fun authenticationProbeContractsRoundTripWithoutEchoingCredentials() {
        val request = AuthenticationProbeRequest(
            address = "dev@local.test",
            provider = Provider.DOVECOT,
            protocol = AuthenticationProtocol.OAUTH_IMAP,
            credentialOverride = "opaque-bearer-token",
            providerAccountId = null,
        )
        val response = AuthenticationProbeResponse(
            address = request.address,
            provider = request.provider,
            protocol = request.protocol,
            success = false,
            providerResponse = "Authentication rejected",
            correlatedLogs = listOf("auth failed for dev@local.test"),
        )

        assertRoundTrip(request)
        assertRoundTrip(response)
        val encodedResponse = json.encodeToString(response)
        kotlin.test.assertFalse("opaque-bearer-token" in encodedResponse)
    }

    @Test
    fun accountListRequiresExactlyOneProviderStatusInProviderOrder() {
        val statuses = providerStatuses()

        assertEquals(
            listOf(Provider.DOVECOT, Provider.STALWART),
            AccountListResponse(emptyList(), statuses).providerStatuses.map(ProviderStatus::provider),
        )
        assertFailsWith<IllegalArgumentException> {
            AccountListResponse(emptyList(), statuses.reversed())
        }
        assertFailsWith<IllegalArgumentException> {
            AccountListResponse(emptyList(), statuses + statuses.first())
        }
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
                providerAccountId = null,
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
                providerAccountId = "account-42",
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

    private fun providerStatuses(): List<ProviderStatus> = listOf(
        ProviderStatus(Provider.DOVECOT, ProviderAvailability.READY),
        ProviderStatus(
            provider = Provider.STALWART,
            availability = ProviderAvailability.DEGRADED,
            message = "Credential probes are not available yet",
        ),
    )
}
