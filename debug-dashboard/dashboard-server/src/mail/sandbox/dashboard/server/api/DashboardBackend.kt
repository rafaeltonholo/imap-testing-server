package mail.sandbox.dashboard.server.api

import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AccountListResponse
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
import mail.sandbox.dashboard.contract.ChangePasswordRequest
import mail.sandbox.dashboard.contract.CredentialUpdateResponse
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.CreateFolderRequest
import mail.sandbox.dashboard.contract.FolderInfo
import mail.sandbox.dashboard.contract.FolderListResponse
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.GenerateMessageResponse
import mail.sandbox.dashboard.contract.LogResponse
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageListResponse
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider

interface DashboardBackend {
    suspend fun listAccounts(): AccountListResponse

    suspend fun createAccount(request: CreateAccountRequest): AccountInfo

    suspend fun deleteAccount(address: String, provider: Provider): OperationResponse

    suspend fun adoptPassword(
        address: String,
        provider: Provider,
        request: AdoptPasswordRequest,
    ): CredentialUpdateResponse

    suspend fun changePassword(
        address: String,
        provider: Provider,
        request: ChangePasswordRequest,
    ): CredentialUpdateResponse

    suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): AuthenticationProbeResponse

    suspend fun logs(service: LogService): LogResponse

    suspend fun accountLogs(address: String, provider: Provider): LogResponse

    suspend fun listFolders(address: String, provider: Provider): FolderListResponse

    suspend fun createFolder(
        address: String,
        provider: Provider,
        request: CreateFolderRequest,
    ): FolderInfo

    suspend fun deleteFolder(
        address: String,
        provider: Provider,
        folderId: String,
    ): OperationResponse

    suspend fun listMessages(
        address: String,
        provider: Provider,
        folderId: String?,
    ): MessageListResponse

    suspend fun readMessage(
        address: String,
        provider: Provider,
        messageId: String,
        folderId: String?,
    ): MessageDetail

    suspend fun mutateMessages(
        address: String,
        provider: Provider,
        request: MutateMessagesRequest,
    ): OperationResponse

    suspend fun generateMessage(request: GenerateMessageRequest): GenerateMessageResponse
}

class DashboardBadRequestException(message: String) : IllegalArgumentException(message)

class DashboardNotFoundException(message: String) : IllegalStateException(message)

internal object UnavailableDashboardBackend : DashboardBackend {
    override suspend fun listAccounts(): AccountListResponse = unavailable()

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo = unavailable()

    override suspend fun deleteAccount(
        address: String,
        provider: Provider,
    ): OperationResponse = unavailable()

    override suspend fun adoptPassword(
        address: String,
        provider: Provider,
        request: AdoptPasswordRequest,
    ): CredentialUpdateResponse = unavailable()

    override suspend fun changePassword(
        address: String,
        provider: Provider,
        request: ChangePasswordRequest,
    ): CredentialUpdateResponse = unavailable()

    override suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): AuthenticationProbeResponse = unavailable()

    override suspend fun logs(service: LogService): LogResponse = unavailable()

    override suspend fun accountLogs(
        address: String,
        provider: Provider,
    ): LogResponse = unavailable()

    override suspend fun listFolders(
        address: String,
        provider: Provider,
    ): FolderListResponse = unavailable()

    override suspend fun createFolder(
        address: String,
        provider: Provider,
        request: CreateFolderRequest,
    ): FolderInfo = unavailable()

    override suspend fun deleteFolder(
        address: String,
        provider: Provider,
        folderId: String,
    ): OperationResponse = unavailable()

    override suspend fun listMessages(
        address: String,
        provider: Provider,
        folderId: String?,
    ): MessageListResponse = unavailable()

    override suspend fun readMessage(
        address: String,
        provider: Provider,
        messageId: String,
        folderId: String?,
    ): MessageDetail = unavailable()

    override suspend fun mutateMessages(
        address: String,
        provider: Provider,
        request: MutateMessagesRequest,
    ): OperationResponse = unavailable()

    override suspend fun generateMessage(
        request: GenerateMessageRequest,
    ): GenerateMessageResponse = unavailable()

    private fun unavailable(): Nothing =
        throw IllegalStateException("Dashboard backend has not been configured")
}
