package mail.sandbox.dashboard.server.local

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider

class LocalDashboardBackendTest {
    @Test
    fun combinesProvidersAndDispatchesAccountCreationToTheSelectedServer() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT)
        val stalwart = RecordingProvider(Provider.STALWART)
        dovecot.accounts += AccountInfo(
            "zeta@local.test",
            Provider.DOVECOT,
            listOf(MailProtocol.IMAP),
        )
        stalwart.accounts += AccountInfo(
            "alpha@local.test",
            Provider.STALWART,
            listOf(MailProtocol.JMAP),
        )
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot, Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
        )

        assertEquals(
            listOf("alpha@local.test", "zeta@local.test"),
            backend.listAccounts().accounts.map(AccountInfo::address),
        )

        val request = CreateAccountRequest(
            address = "new@local.test",
            password = "password",
            provider = Provider.STALWART,
            protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
        )
        assertEquals(request.address, backend.createAccount(request).address)
        assertEquals(listOf(request), stalwart.createdAccounts)
        assertTrue(dovecot.createdAccounts.isEmpty())
    }

    @Test
    fun generationCreatesRfcMessagesAndInjectsThemIntoTheRequestedProvider() = runBlocking {
        val dovecot = RecordingProvider(Provider.DOVECOT)
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to dovecot),
            logSource = RecordingLogs(),
        )

        val response = backend.generateMessage(
            GenerateMessageRequest(
                targetAccount = "dev@local.test",
                provider = Provider.DOVECOT,
                sourceType = MessageSourceType.TEXT,
                content = "A body",
                subject = "A subject",
                count = 2,
            ),
        )

        assertEquals(listOf("message-1", "message-2"), response.messageIds)
        assertTrue(response.operation.success)
        assertEquals(2, dovecot.injectedMessages.size)
        assertTrue(dovecot.injectedMessages.all { "Subject: A subject" in it.rawEml })
    }

    @Test
    fun smtpGenerationUsesTheProvidersRealDeliveryPath() = runBlocking {
        val stalwart = RecordingProvider(Provider.STALWART)
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.STALWART to stalwart),
            logSource = RecordingLogs(),
        )

        val response = backend.generateMessage(
            GenerateMessageRequest(
                targetAccount = "dev@local.test",
                provider = Provider.STALWART,
                sourceType = MessageSourceType.RANDOM,
                deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
                seed = 42,
            ),
        )

        assertEquals(listOf("delivered-1"), response.messageIds)
        assertEquals("Delivered 1 message", response.operation.message)
        assertEquals(1, stalwart.deliveredMessages.size)
        assertTrue(stalwart.injectedMessages.isEmpty())
    }

    @Test
    fun dovecotAccountLogsCombineDovecotAndPostfixEvidence() = runBlocking {
        val logs = RecordingLogs()
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.DOVECOT to RecordingProvider(Provider.DOVECOT)),
            logSource = logs,
        )

        assertEquals(
            listOf("[dovecot] line-DOVECOT", "[postfix] line-POSTFIX"),
            backend.accountLogs("dev@local.test", Provider.DOVECOT).lines,
        )
        assertEquals(
            listOf(
                LogRead(
                    LogService.DOVECOT,
                    DashboardLogAccount("dev@local.test"),
                    500,
                ),
                LogRead(
                    LogService.POSTFIX,
                    DashboardLogAccount("dev@local.test"),
                    500,
                ),
            ),
            logs.requests,
        )
    }

    @Test
    fun stalwartAccountLogsStayOnTheDedicatedStalwartChannel() = runBlocking {
        val logs = RecordingLogs()
        val stalwart = RecordingProvider(Provider.STALWART).apply {
            logAccount = DashboardLogAccount("dev@local.test", providerAccountId = "c")
        }
        val backend = LocalDashboardBackend(
            providers = mapOf(Provider.STALWART to stalwart),
            logSource = logs,
        )

        assertEquals(
            listOf("line-STALWART"),
            backend.accountLogs("dev@local.test", Provider.STALWART).lines,
        )
        assertEquals(
            LogRead(
                LogService.STALWART,
                DashboardLogAccount("dev@local.test", providerAccountId = "c"),
                500,
            ),
            logs.requests.single(),
        )
    }
}

private class RecordingLogs : DashboardLogSource {
    val requests = mutableListOf<LogRead>()

    override fun read(
        service: LogService,
        account: DashboardLogAccount?,
        limit: Int,
    ): LogResponse {
        requests += LogRead(service, account, limit)
        return LogResponse(service, account?.address, listOf("line-${service.name}"))
    }
}

private data class LogRead(
    val service: LogService,
    val account: DashboardLogAccount?,
    val limit: Int,
)

private class RecordingProvider(
    override val provider: Provider,
) : LocalProviderOperations {
    val accounts = mutableListOf<AccountInfo>()
    val createdAccounts = mutableListOf<CreateAccountRequest>()
    val injectedMessages = mutableListOf<GeneratedMessage>()
    val deliveredMessages = mutableListOf<GeneratedMessage>()
    var logAccount = DashboardLogAccount("dev@local.test")

    override suspend fun listAccounts(): List<AccountInfo> = accounts

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo {
        createdAccounts += request
        return AccountInfo(request.address, request.provider, request.protocols)
    }

    override suspend fun dashboardLogAccount(address: String): DashboardLogAccount = logAccount

    override suspend fun deleteAccount(address: String) = Unit

    override suspend fun changePassword(address: String, newPassword: String) = Unit

    override suspend fun listFolders(address: String): List<FolderInfo> = emptyList()

    override suspend fun createFolder(address: String, name: String): FolderInfo =
        FolderInfo(name, name, 0, 0)

    override suspend fun deleteFolder(address: String, folderId: String) = Unit

    override suspend fun listMessages(
        address: String,
        folderId: String?,
    ): List<MessageSummary> = emptyList()

    override suspend fun readMessage(
        address: String,
        messageId: String,
        folderId: String?,
    ): MessageDetail = error("not used")

    override suspend fun mutateMessages(
        address: String,
        request: MutateMessagesRequest,
    ): OperationResponse = OperationResponse(true, request.action.name)

    override suspend fun injectMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
        injectedMessages += messages
        return messages.indices.map { "message-${it + 1}" }
    }

    override suspend fun deliverMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String> {
        deliveredMessages += messages
        return messages.indices.map { "delivered-${it + 1}" }
    }
}
