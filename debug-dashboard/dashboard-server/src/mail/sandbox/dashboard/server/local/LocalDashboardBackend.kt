package mail.sandbox.dashboard.server.local

import java.nio.file.Path
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AccountListResponse
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.ChangePasswordRequest
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.CredentialUpdateResponse
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
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.contract.ProviderStatus
import mail.sandbox.dashboard.server.api.DashboardBackend
import mail.sandbox.dashboard.server.api.DashboardNotFoundException
import mail.sandbox.dashboard.server.provider.dovecot.DovecotProductAdapter

internal interface LocalProviderOperations {
    val provider: Provider

    suspend fun listAccounts(): List<AccountInfo>

    fun providerStatus(): ProviderStatus = ProviderStatus(
        provider = provider,
        availability = ProviderAvailability.READY,
    )

    suspend fun createAccount(request: CreateAccountRequest): AccountInfo

    suspend fun dashboardLogAccount(
        address: String,
        providerAccountId: String? = null,
    ): DashboardLogAccount

    suspend fun deleteAccount(address: String, providerAccountId: String? = null)

    suspend fun adoptPassword(
        address: String,
        request: AdoptPasswordRequest,
        providerAccountId: String? = null,
    ): CredentialUpdateResponse = unavailableCredentialUpdate(
        address,
        "Password verification is unavailable for ${provider.name}",
    )

    suspend fun changePassword(
        address: String,
        newPassword: String,
        providerAccountId: String? = null,
    ): CredentialUpdateResponse

    suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): LocalAuthenticationProbeResult = LocalAuthenticationProbeResult(
        response = AuthenticationProbeResponse(
            address = request.address,
            provider = request.provider,
            protocol = request.protocol,
            success = false,
            providerResponse = "Authentication probes are unavailable for ${provider.name}",
            correlatedLogs = emptyList(),
        ),
    )

    suspend fun listFolders(address: String, providerAccountId: String? = null): List<FolderInfo>

    suspend fun createFolder(
        address: String,
        name: String,
        providerAccountId: String? = null,
    ): FolderInfo

    suspend fun deleteFolder(
        address: String,
        folderId: String,
        providerAccountId: String? = null,
    )

    suspend fun listMessages(
        address: String,
        folderId: String?,
        providerAccountId: String? = null,
    ): List<MessageSummary>

    suspend fun readMessage(
        address: String,
        messageId: String,
        folderId: String?,
        providerAccountId: String? = null,
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

    private fun unavailableCredentialUpdate(
        address: String,
        message: String,
    ): CredentialUpdateResponse = CredentialUpdateResponse(
        address = address,
        provider = provider,
        readiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
        operation = OperationResponse(success = false, message = message),
    )
}

/** Provider-only probe metadata. Secrets never cross the serialized API boundary. */
internal data class LocalAuthenticationProbeResult(
    val response: AuthenticationProbeResponse,
    val secretsToRedact: List<String> = emptyList(),
) {
    override fun toString(): String =
        "LocalAuthenticationProbeResult(response=redacted, secretCount=${secretsToRedact.size})"
}

internal class LocalDashboardBackend(
    providers: Map<Provider, LocalProviderOperations>,
    private val logSource: DashboardLogSource,
    private val messageGenerator: MessageGenerator = MessageGenerator(),
    private val cachedAccounts: () -> List<LocalAccountRecord> = { emptyList() },
    private val authenticationLogPollAttempts: Int = 3,
    private val authenticationLogPollDelayMillis: Long = 50,
) : DashboardBackend, AutoCloseable {
    private val providers: Map<Provider, LocalProviderOperations> = providers.toMap()

    init {
        require(this.providers.isNotEmpty()) { "At least one dashboard provider is required" }
        require(this.providers.all { (key, value) -> key == value.provider }) {
            "Dashboard provider map is inconsistent"
        }
        require(authenticationLogPollAttempts in 1..10) {
            "Authentication log polling must be bounded"
        }
        require(authenticationLogPollDelayMillis in 0..1_000) {
            "Authentication log polling delay must be bounded"
        }
    }

    override suspend fun listAccounts(): AccountListResponse {
        val cached = try {
            cachedAccounts()
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            emptyList()
        }
        val accounts = mutableListOf<AccountInfo>()
        val statuses = mutableListOf<ProviderStatus>()
        Provider.entries.forEach { provider ->
            val operations = providers[provider]
            if (operations == null) {
                val message = "${provider.displayName()} is not configured"
                statuses += ProviderStatus(provider, ProviderAvailability.UNAVAILABLE, message)
                accounts += staleAccounts(cached, provider, message)
            } else {
                try {
                    val live = operations.listAccounts()
                    require(live.all { it.provider == provider }) {
                        "${provider.displayName()} returned an account for another provider"
                    }
                    val status = operations.providerStatus()
                    require(status.provider == provider) {
                        "${provider.displayName()} returned an inconsistent provider status"
                    }
                    accounts += live
                    statuses += status
                } catch (cancellation: CancellationException) {
                    throw cancellation
                } catch (failure: Exception) {
                    val message = failure.message
                        ?.take(PROVIDER_STATUS_MESSAGE_LIMIT)
                        ?.ifBlank { null }
                        ?: "${provider.displayName()} account listing failed"
                    statuses += ProviderStatus(
                        provider = provider,
                        availability = ProviderAvailability.UNAVAILABLE,
                        message = message,
                    )
                    accounts += staleAccounts(cached, provider, message)
                }
            }
        }
        return AccountListResponse(
            accounts = accounts.sortedWith(
                compareBy(AccountInfo::address, { it.provider.ordinal }),
            ),
            providerStatuses = statuses,
        )
    }

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo =
        operations(request.provider).createAccount(request)

    override suspend fun deleteAccount(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): OperationResponse {
        operations(provider).deleteAccount(address, providerAccountId)
        return success("Account deleted from ${provider.displayName()}")
    }

    override suspend fun adoptPassword(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: AdoptPasswordRequest,
    ): CredentialUpdateResponse =
        operations(provider).adoptPassword(address, request, providerAccountId)

    override suspend fun changePassword(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: ChangePasswordRequest,
    ): CredentialUpdateResponse =
        operations(provider).changePassword(address, request.newPassword, providerAccountId)

    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): AuthenticationProbeResponse {
        val operations = operations(request.provider)
        val logAccount = operations.dashboardLogAccount(
            request.address,
            request.providerAccountId,
        )
        val service = request.logService()
        val cursor = logSource.snapshot(service, logAccount, AUTHENTICATION_LOG_LIMIT)
        val probeResult = operations.probeAuthentication(request)
        val secretsToRedact = (probeResult.secretsToRedact + request.credentialOverride)
            .filterNotNull()
            .filter(String::isNotEmpty)
            .distinct()
            .sortedByDescending(String::length)
        val response = probeResult.response.redact(secretsToRedact)
        var correlated = emptyList<String>()
        repeat(authenticationLogPollAttempts) { attempt ->
            if (attempt > 0 && authenticationLogPollDelayMillis > 0) {
                delay(authenticationLogPollDelayMillis)
            }
            correlated = logSource.readAfter(
                service = service,
                account = logAccount,
                cursor = cursor,
                limit = AUTHENTICATION_LOG_LIMIT,
            ).lines.map { line -> line.redact(secretsToRedact) }
            if (correlated.isNotEmpty()) {
                return response.copy(correlatedLogs = correlated.takeLast(AUTHENTICATION_LOG_LIMIT))
            }
        }
        return response.copy(correlatedLogs = correlated)
    }

    override suspend fun logs(service: LogService): LogResponse = logSource.read(service)

    override suspend fun accountLogs(
        address: String,
        provider: Provider,
        providerAccountId: String?,
    ): LogResponse {
        val account = operations(provider).dashboardLogAccount(address, providerAccountId)
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
        providerAccountId: String?,
    ): FolderListResponse = FolderListResponse(
        operations(provider).listFolders(address, providerAccountId),
    )

    override suspend fun createFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: CreateFolderRequest,
    ): FolderInfo = operations(provider).createFolder(
        address,
        request.name,
        providerAccountId,
    )

    override suspend fun deleteFolder(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String,
    ): OperationResponse {
        operations(provider).deleteFolder(address, folderId, providerAccountId)
        return success("Folder deleted")
    }

    override suspend fun listMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        folderId: String?,
    ): MessageListResponse = MessageListResponse(
        operations(provider).listMessages(address, folderId, providerAccountId),
    )

    override suspend fun readMessage(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        messageId: String,
        folderId: String?,
    ): MessageDetail = operations(provider).readMessage(
        address,
        messageId,
        folderId,
        providerAccountId,
    )

    override suspend fun mutateMessages(
        address: String,
        provider: Provider,
        providerAccountId: String?,
        request: MutateMessagesRequest,
    ): OperationResponse {
        require(request.providerAccountId == providerAccountId) {
            "Message action provider identity does not match the route"
        }
        return operations(provider).mutateMessages(address, request)
    }

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
            try {
                provider.close()
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (_: Exception) {
                // Closing one provider must not prevent the remaining providers from closing.
            }
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
                        adapter = DovecotProductAdapter.dashboard(repositoryRoot),
                        catalog = catalog,
                    ),
                    Provider.STALWART to createStalwartDashboardProvider(
                        repositoryRoot = repositoryRoot,
                        catalog = catalog,
                        environment = environment,
                    ),
                ),
                logSource = DockerComposeLogSource(repositoryRoot),
                cachedAccounts = catalog::list,
            )
        }

        private const val AUTHENTICATION_LOG_LIMIT = 500
        private const val PROVIDER_STATUS_MESSAGE_LIMIT = 240
    }

    private fun staleAccounts(
        cached: List<LocalAccountRecord>,
        provider: Provider,
        message: String,
    ): List<AccountInfo> = cached.filter { it.provider == provider }.map { record ->
        AccountInfo(
            address = record.address,
            provider = record.provider,
            protocols = record.protocols,
            credentialReadiness = CredentialReadiness.PROVIDER_UNAVAILABLE,
            providerAccountId = record.providerAccountId,
            readinessMessage = message,
            stale = true,
        )
    }
}

private fun AuthenticationProbeRequest.logService(): LogService = when (provider) {
    Provider.STALWART -> LogService.STALWART
    Provider.DOVECOT -> when (protocol) {
        AuthenticationProtocol.SMTP,
        AuthenticationProtocol.OAUTH_SMTP,
        -> LogService.POSTFIX
        AuthenticationProtocol.IMAP,
        AuthenticationProtocol.POP3,
        AuthenticationProtocol.OAUTH_IMAP,
        -> LogService.DOVECOT
        AuthenticationProtocol.JMAP -> error("Dovecot does not support JMAP probes")
    }
}

private fun Provider.displayName(): String = when (this) {
    Provider.DOVECOT -> "Dovecot"
    Provider.STALWART -> "Stalwart"
}

private fun AuthenticationProbeResponse.redact(credentials: List<String>): AuthenticationProbeResponse =
    copy(
        providerResponse = providerResponse.redact(credentials),
        correlatedLogs = correlatedLogs.map { line -> line.redact(credentials) },
    )

private fun String.redact(credentials: List<String>): String =
    credentials.fold(this) { redacted, credential ->
        redacted.replace(credential, "[redacted]")
    }
