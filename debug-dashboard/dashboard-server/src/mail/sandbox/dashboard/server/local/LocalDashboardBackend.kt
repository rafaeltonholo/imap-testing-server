package mail.sandbox.dashboard.server.local

import java.nio.file.Path
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AccountListResponse
import mail.sandbox.dashboard.contract.ChangePasswordRequest
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.CreateFolderRequest
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.FolderListResponse
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.GenerateMessageResponse
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageListResponse
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.server.api.DashboardBackend
import mail.sandbox.dashboard.server.api.DashboardNotFoundException
import mail.sandbox.dashboard.server.provider.dovecot.DovecotProductAdapter

internal interface LocalProviderOperations {
    val provider: Provider

    suspend fun listAccounts(): List<AccountInfo>

    suspend fun createAccount(request: CreateAccountRequest): AccountInfo

    suspend fun dashboardLogAccount(address: String): DashboardLogAccount

    suspend fun deleteAccount(address: String)

    suspend fun changePassword(address: String, newPassword: String)

    suspend fun listFolders(address: String): List<FolderInfo>

    suspend fun createFolder(address: String, name: String): FolderInfo

    suspend fun deleteFolder(address: String, folderId: String)

    suspend fun listMessages(address: String, folderId: String?): List<MessageSummary>

    suspend fun readMessage(
        address: String,
        messageId: String,
        folderId: String?,
    ): MessageDetail

    suspend fun mutateMessages(
        address: String,
        request: MutateMessagesRequest,
    ): OperationResponse

    suspend fun injectMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String>

    suspend fun deliverMessages(
        request: GenerateMessageRequest,
        messages: List<GeneratedMessage>,
    ): List<String>
}

internal class LocalDashboardBackend(
    providers: Map<Provider, LocalProviderOperations>,
    private val logSource: DashboardLogSource,
    private val messageGenerator: MessageGenerator = MessageGenerator(),
) : DashboardBackend, AutoCloseable {
    private val providers: Map<Provider, LocalProviderOperations> = providers.toMap()

    init {
        require(this.providers.isNotEmpty()) { "At least one dashboard provider is required" }
        require(this.providers.all { (key, value) -> key == value.provider }) {
            "Dashboard provider map is inconsistent"
        }
    }

    override suspend fun listAccounts(): AccountListResponse = AccountListResponse(
        accounts = providers.values
            .flatMap { it.listAccounts() }
            .sortedWith(compareBy(AccountInfo::address, { it.provider.ordinal })),
    )

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo =
        operations(request.provider).createAccount(request)

    override suspend fun deleteAccount(
        address: String,
        provider: Provider,
    ): OperationResponse {
        operations(provider).deleteAccount(address)
        return success("Account deleted from ${provider.displayName()}")
    }

    override suspend fun changePassword(
        address: String,
        provider: Provider,
        request: ChangePasswordRequest,
    ): OperationResponse {
        operations(provider).changePassword(address, request.newPassword)
        return success("Password changed on ${provider.displayName()}")
    }

    override suspend fun logs(service: LogService): LogResponse = logSource.read(service)

    override suspend fun accountLogs(address: String, provider: Provider): LogResponse {
        val account = operations(provider).dashboardLogAccount(address)
        return when (provider) {
            Provider.DOVECOT -> LogResponse(
                service = LogService.DOVECOT,
                account = account.address,
                lines = listOf(LogService.DOVECOT, LogService.POSTFIX)
                    .flatMap { service ->
                        logSource.read(service, account = account).lines.map { line ->
                            "[${service.name.lowercase()}] $line"
                        }
                    }
                    .takeLast(ACCOUNT_LOG_LIMIT),
            )
            Provider.STALWART -> logSource.read(LogService.STALWART, account = account)
        }
    }

    override suspend fun listFolders(
        address: String,
        provider: Provider,
    ): FolderListResponse = FolderListResponse(operations(provider).listFolders(address))

    override suspend fun createFolder(
        address: String,
        provider: Provider,
        request: CreateFolderRequest,
    ): FolderInfo = operations(provider).createFolder(address, request.name)

    override suspend fun deleteFolder(
        address: String,
        provider: Provider,
        folderId: String,
    ): OperationResponse {
        operations(provider).deleteFolder(address, folderId)
        return success("Folder deleted")
    }

    override suspend fun listMessages(
        address: String,
        provider: Provider,
        folderId: String?,
    ): MessageListResponse = MessageListResponse(
        operations(provider).listMessages(address, folderId),
    )

    override suspend fun readMessage(
        address: String,
        provider: Provider,
        messageId: String,
        folderId: String?,
    ): MessageDetail = operations(provider).readMessage(address, messageId, folderId)

    override suspend fun mutateMessages(
        address: String,
        provider: Provider,
        request: MutateMessagesRequest,
    ): OperationResponse = operations(provider).mutateMessages(address, request)

    override suspend fun generateMessage(
        request: GenerateMessageRequest,
    ): GenerateMessageResponse {
        val generated = messageGenerator.generate(request)
        val ids = when (request.deliveryMode) {
            MessageDeliveryMode.DIRECT_APPEND ->
                operations(request.provider).injectMessages(request, generated)
            MessageDeliveryMode.SMTP_DELIVERY ->
                operations(request.provider).deliverMessages(request, generated)
        }
        val action = when (request.deliveryMode) {
            MessageDeliveryMode.DIRECT_APPEND -> "Appended"
            MessageDeliveryMode.SMTP_DELIVERY -> "Delivered"
        }
        return GenerateMessageResponse(
            messageIds = ids,
            operation = success(
                "$action ${generated.size} message${if (generated.size == 1) "" else "s"}",
            ),
        )
    }

    override fun close() {
        providers.values.filterIsInstance<AutoCloseable>().forEach { provider ->
            runCatching(provider::close)
        }
    }

    private fun operations(provider: Provider): LocalProviderOperations =
        providers[provider]
            ?: throw DashboardNotFoundException("${provider.displayName()} is not configured")

    private fun success(message: String): OperationResponse =
        OperationResponse(success = true, message = message)

    companion object {
        private const val ACCOUNT_LOG_LIMIT = 500

        fun production(
            repositoryRoot: Path = Path.of(System.getProperty("user.dir"))
                .toAbsolutePath()
                .normalize(),
            environment: Map<String, String> = System.getenv(),
        ): LocalDashboardBackend {
            val catalog = LocalAccountCatalog.production(repositoryRoot)
            return LocalDashboardBackend(
                providers = mapOf(
                    Provider.DOVECOT to DovecotDashboardProvider(
                        adapter = DovecotProductAdapter.dashboard(),
                        catalog = catalog,
                    ),
                    Provider.STALWART to createStalwartDashboardProvider(
                        repositoryRoot = repositoryRoot,
                        catalog = catalog,
                        environment = environment,
                    ),
                ),
                logSource = DockerComposeLogSource(repositoryRoot),
            )
        }
    }
}

private fun Provider.displayName(): String = when (this) {
    Provider.DOVECOT -> "Dovecot"
    Provider.STALWART -> "Stalwart"
}
