package mail.sandbox.dashboard.web

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlin.js.ExperimentalWasmJsInterop
import kotlin.js.JsString
import kotlin.js.toJsString
import kotlinx.browser.window
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.await
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.AccountListResponse
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeResponse
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
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageListResponse
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.ProviderAvailability
import mail.sandbox.dashboard.contract.ProviderStatus
import mail.sandbox.dashboard.contract.Routes
import mail.sandbox.dashboard.contract.requireAchievedOperation
import mail.sandbox.dashboard.contract.support.LatestRequestTracker
import mail.sandbox.dashboard.contract.targetsExactly
import org.w3c.fetch.Headers
import org.w3c.fetch.RequestInit

internal data class AccountTarget(
    val address: String,
    val provider: Provider,
    val providerAccountId: String?,
)

internal fun AccountInfo.target(): AccountTarget =
    AccountTarget(address, provider, providerAccountId)

internal val AccountTarget.displayName: String
    get() = "${provider.displayName()} · $address"

internal fun Provider.displayName(): String = when (this) {
    Provider.DOVECOT -> "Dovecot"
    Provider.STALWART -> "Stalwart"
}

@OptIn(ExperimentalWasmJsInterop::class)
internal class DashboardApi {
    private val json = Json {
        ignoreUnknownKeys = true
    }

    suspend fun listAccounts(): AccountListResponse = get(Routes.ACCOUNTS)

    suspend fun createAccount(request: CreateAccountRequest): AccountInfo =
        post(Routes.ACCOUNTS, json.encodeToString(request))

    suspend fun deleteAccount(target: AccountTarget): OperationResponse =
        delete(targetedRoute(accountRoute(target), target))

    suspend fun changePassword(
        target: AccountTarget,
        request: ChangePasswordRequest,
    ): CredentialUpdateResponse = put(
        targetedRoute("${accountRoute(target)}/password", target),
        json.encodeToString(request),
    )

    suspend fun adoptPassword(
        target: AccountTarget,
        request: AdoptPasswordRequest,
    ): CredentialUpdateResponse = post(
        targetedRoute("${accountRoute(target)}/password/verify", target),
        json.encodeToString(request),
    )

    suspend fun probeAuthentication(
        request: AuthenticationProbeRequest,
    ): AuthenticationProbeResponse = post(
        Routes.AUTHENTICATION_PROBES,
        json.encodeToString(request),
    )

    suspend fun logs(service: LogService): LogResponse =
        get("${Routes.LOGS}?service=${encodeComponent(service.name)}")

    suspend fun accountLogs(target: AccountTarget): LogResponse =
        get(
            targetedRoute(
                "${Routes.LOGS}/accounts/${encodeComponent(target.address)}/providers/${target.provider.name.lowercase()}",
                target,
            ),
        )

    suspend fun folders(target: AccountTarget): FolderListResponse =
        get(targetedRoute("${accountRoute(target)}/folders", target))

    suspend fun createFolder(
        target: AccountTarget,
        request: CreateFolderRequest,
    ): FolderInfo = post(
        targetedRoute("${accountRoute(target)}/folders", target),
        json.encodeToString(request),
    )

    suspend fun deleteFolder(
        target: AccountTarget,
        folderId: String,
    ): OperationResponse = delete(
        targetedRoute(
            "${accountRoute(target)}/folders/${encodeComponent(folderId)}",
            target,
        ),
    )

    suspend fun messages(
        target: AccountTarget,
        folderId: String?,
    ): MessageListResponse {
        return get(
            targetedRoute(
                "${accountRoute(target)}/messages",
                target,
                folderId?.let { "folderId" to it },
            ),
        )
    }

    suspend fun message(
        target: AccountTarget,
        messageId: String,
        folderId: String?,
    ): MessageDetail {
        return get(
            targetedRoute(
                "${accountRoute(target)}/messages/${encodeComponent(messageId)}",
                target,
                folderId?.let { "folderId" to it },
            ),
        )
    }

    suspend fun mutateMessages(
        target: AccountTarget,
        request: MutateMessagesRequest,
    ): OperationResponse = post(
        targetedRoute("${accountRoute(target)}/message-actions", target),
        json.encodeToString(request),
    )

    suspend fun generateMessage(request: GenerateMessageRequest): GenerateMessageResponse =
        post(Routes.GENERATE_MESSAGE, json.encodeToString(request))

    private fun accountRoute(target: AccountTarget): String =
        "${Routes.ACCOUNTS}/${encodeComponent(target.address)}/providers/${target.provider.name.lowercase()}"

    private fun targetedRoute(
        path: String,
        target: AccountTarget,
        extraParameter: Pair<String, String>? = null,
    ): String {
        val parameters = listOfNotNull(
            target.providerAccountId?.let { "providerAccountId" to it },
            extraParameter,
        )
        if (parameters.isEmpty()) return path
        return path + parameters.joinToString(prefix = "?", separator = "&") { (name, value) ->
            "$name=${encodeComponent(value)}"
        }
    }

    private suspend inline fun <reified T> get(path: String): T =
        decode(request(path, "GET", null))

    private suspend inline fun <reified T> post(path: String, body: String): T =
        decode(request(path, "POST", body))

    private suspend inline fun <reified T> put(path: String, body: String): T =
        decode(request(path, "PUT", body))

    private suspend inline fun <reified T> delete(path: String): T =
        decode(request(path, "DELETE", null))

    private inline fun <reified T> decode(body: String): T = json.decodeFromString(body)

    private suspend fun request(
        path: String,
        method: String,
        body: String?,
    ): String {
        val headers = Headers().apply {
            set("Accept", "application/json")
            if (body != null) set("Content-Type", "application/json")
        }
        val requestInit = if (body == null) {
            requestInitWithoutBody(method.toJsString(), headers)
        } else {
            requestInitWithBody(method.toJsString(), headers, body.toJsString())
        }
        val response = window.fetch(
            path,
            requestInit,
        ).await()
        val responseBody: JsString = response.text().await()
        val text = responseBody.toString()
        if (!response.ok) {
            throw DashboardApiException(
                errorMessage(text).ifBlank {
                    "Request failed with HTTP ${response.status}"
                },
            )
        }
        return text
    }

    private fun errorMessage(body: String): String = runCatching {
        json.parseToJsonElement(body).jsonObject["message"]?.jsonPrimitive?.content.orEmpty()
    }.getOrDefault("")
}

private class DashboardApiException(message: String) : IllegalStateException(message)

@OptIn(ExperimentalWasmJsInterop::class)
private fun encodeComponent(value: String): String =
    encodeUriComponent(value.toJsString()).toString()

@OptIn(ExperimentalWasmJsInterop::class)
@JsFun("(value) => encodeURIComponent(value)")
private external fun encodeUriComponent(value: JsString): JsString

/**
 * Kotlin/Wasm's generated RequestInit dictionary currently writes nullable defaults as
 * explicit JavaScript null values. Chromium rejects those for enum-backed fields such as
 * RequestInit.cache. Construct a sparse JavaScript dictionary so only the requested fields
 * cross the interop boundary.
 */
@OptIn(ExperimentalWasmJsInterop::class)
@JsFun("(method, headers) => ({ method, headers })")
private external fun requestInitWithoutBody(
    method: JsString,
    headers: Headers,
): RequestInit

@OptIn(ExperimentalWasmJsInterop::class)
@JsFun("(method, headers, body) => ({ method, headers, body })")
private external fun requestInitWithBody(
    method: JsString,
    headers: Headers,
    body: JsString,
): RequestInit

internal class DashboardController(
    private val api: DashboardApi = DashboardApi(),
) {
    private var workspaceRequestGeneration = 0L
    private val accountLogRequests = LatestRequestTracker<AccountTarget>()
    private val globalLogRequests = LatestRequestTracker<LogService>()

    var accounts by mutableStateOf<List<AccountInfo>>(emptyList())
        private set
    var providerStatuses by mutableStateOf<List<ProviderStatus>>(emptyList())
        private set
    var selectedTarget by mutableStateOf<AccountTarget?>(null)
        private set
    var folders by mutableStateOf<List<FolderInfo>>(emptyList())
        private set
    var selectedFolderId by mutableStateOf<String?>(null)
        private set
    var messages by mutableStateOf<List<MessageSummary>>(emptyList())
        private set
    var selectedMessage by mutableStateOf<MessageDetail?>(null)
        private set
    var selectedMessageId by mutableStateOf<String?>(null)
        private set
    var accountLogs by mutableStateOf<LogResponse?>(null)
        private set
    var globalLogs by mutableStateOf<LogResponse?>(null)
        private set
    var globalLogService by mutableStateOf(LogService.ALL)
        private set
    var accountsLoading by mutableStateOf(false)
        private set
    var workspaceLoading by mutableStateOf(false)
        private set
    var messageLoading by mutableStateOf(false)
        private set
    var accountLogsLoading by mutableStateOf(false)
        private set
    var globalLogsLoading by mutableStateOf(false)
        private set
    var busyLabel by mutableStateOf<String?>(null)
        private set
    var accountError by mutableStateOf<String?>(null)
        private set
    var workspaceError by mutableStateOf<String?>(null)
        private set
    var accountLogsError by mutableStateOf<String?>(null)
        private set
    var globalLogsError by mutableStateOf<String?>(null)
        private set
    var operationError by mutableStateOf<String?>(null)
        private set
    var lastReceipt by mutableStateOf<String?>(null)
        private set
    var authenticationProbe by mutableStateOf<AuthenticationProbeResponse?>(null)
        private set
    var authenticationProbeLoading by mutableStateOf(false)
        private set
    var authenticationProbeError by mutableStateOf<String?>(null)
        private set

    val selectedAccount: AccountInfo?
        get() = selectedTarget?.let { target ->
            accounts.firstOrNull { it.target() == target }
        }

    val selectedFolder: FolderInfo?
        get() = folders.firstOrNull { it.id == selectedFolderId }

    val selectedSummary: MessageSummary?
        get() = messages.firstOrNull { it.id == selectedMessageId }

    val mailActionsEnabled: Boolean
        get() = selectedAccount?.credentialReadiness == CredentialReadiness.READY

    suspend fun initialize() {
        refreshAccounts()
        refreshGlobalLogs(LogService.ALL)
    }

    suspend fun refreshAccounts(preferredTarget: AccountTarget? = selectedTarget) {
        accountsLoading = true
        accountError = null
        try {
            val previousTarget = selectedTarget
            val response = api.listAccounts()
            accounts = response.accounts
            providerStatuses = response.providerStatuses
            val next = preferredTarget?.takeIf(::containsTarget)
                ?: selectedTarget?.takeIf(::containsTarget)
                ?: accounts.firstOrNull()?.target()
            selectedTarget = next
            if (next != previousTarget) clearAuthenticationProbe()
            if (next == null) {
                clearWorkspace()
            } else {
                refreshWorkspace()
            }
        } catch (failure: Throwable) {
            failure.rethrowIfCancellation()
            accountError = failure.userMessage("Accounts could not be loaded")
            if (providerStatuses.isEmpty()) {
                providerStatuses = Provider.entries.map { provider ->
                    ProviderStatus(
                        provider = provider,
                        availability = ProviderAvailability.UNAVAILABLE,
                        message = "Provider status could not be loaded",
                    )
                }
            }
        } finally {
            accountsLoading = false
        }
    }

    suspend fun selectAccount(target: AccountTarget) {
        if (selectedTarget == target && folders.isNotEmpty()) return
        selectedTarget = target
        clearAuthenticationProbe()
        clearWorkspace()
        refreshWorkspace()
    }

    suspend fun refreshWorkspace(
        keepFolderId: String? = selectedFolderId,
        keepMessageId: String? = selectedMessageId,
    ) {
        val target = selectedTarget ?: return clearWorkspace()
        if (!mailActionsEnabled) {
            beginWorkspaceRequest()
            clearMailboxState()
            workspaceError = null
            refreshAccountLogs()
            return
        }
        val requestGeneration = beginWorkspaceRequest()
        workspaceLoading = true
        workspaceError = null
        try {
            val loadedFolders = api.folders(target).folders
            if (!isCurrentWorkspaceRequest(requestGeneration, target)) return

            folders = loadedFolders
            selectedFolderId = chooseFolder(loadedFolders, keepFolderId)?.id
            messages = emptyList()
            val loadedMessages = api.messages(target, selectedFolderId).messages
            if (!isCurrentWorkspaceRequest(requestGeneration, target)) return

            messages = loadedMessages
            selectedMessageId = keepMessageId?.takeIf { id -> messages.any { it.id == id } }
            selectedMessage = null
            val messageId = selectedMessageId
            if (messageId != null) {
                val loadedMessage = api.message(target, messageId, selectedFolderId)
                if (!isCurrentWorkspaceRequest(requestGeneration, target) || selectedMessageId != messageId) return
                selectedMessage = loadedMessage
            }
        } catch (failure: Throwable) {
            failure.rethrowIfCancellation()
            if (isCurrentWorkspaceRequest(requestGeneration, target)) {
                workspaceError = failure.userMessage("Mailbox state could not be loaded")
            }
        } finally {
            if (isCurrentWorkspaceRequest(requestGeneration, target)) {
                workspaceLoading = false
            }
        }
        if (isCurrentWorkspaceRequest(requestGeneration, target)) {
            refreshAccountLogs()
        }
    }

    suspend fun selectFolder(folderId: String) {
        if (!mailActionsEnabled) return
        val target = selectedTarget ?: return
        val requestGeneration = beginWorkspaceRequest()
        selectedFolderId = folderId
        messages = emptyList()
        selectedMessageId = null
        selectedMessage = null
        workspaceLoading = true
        workspaceError = null
        try {
            val loadedMessages = api.messages(target, folderId).messages
            if (!isCurrentWorkspaceRequest(requestGeneration, target) || selectedFolderId != folderId) return
            messages = loadedMessages
        } catch (failure: Throwable) {
            failure.rethrowIfCancellation()
            if (isCurrentWorkspaceRequest(requestGeneration, target) && selectedFolderId == folderId) {
                workspaceError = failure.userMessage("Messages could not be loaded")
            }
        } finally {
            if (isCurrentWorkspaceRequest(requestGeneration, target) && selectedFolderId == folderId) {
                workspaceLoading = false
            }
        }
    }

    suspend fun selectMessage(summary: MessageSummary) {
        if (!mailActionsEnabled) return
        val target = selectedTarget ?: return
        val requestGeneration = workspaceRequestGeneration
        selectedMessageId = summary.id
        selectedMessage = null
        messageLoading = true
        workspaceError = null
        try {
            val loadedMessage = api.message(target, summary.id, summary.folderId)
            if (
                isCurrentWorkspaceRequest(requestGeneration, target) &&
                selectedFolderId == summary.folderId &&
                selectedMessageId == summary.id
            ) {
                selectedMessage = loadedMessage
            }
        } catch (failure: Throwable) {
            failure.rethrowIfCancellation()
            if (
                isCurrentWorkspaceRequest(requestGeneration, target) &&
                selectedFolderId == summary.folderId &&
                selectedMessageId == summary.id
            ) {
                workspaceError = failure.userMessage("The message could not be read")
            }
        } finally {
            if (
                isCurrentWorkspaceRequest(requestGeneration, target) &&
                selectedFolderId == summary.folderId &&
                selectedMessageId == summary.id
            ) {
                messageLoading = false
            }
        }
    }

    suspend fun refreshGlobalLogs(service: LogService = globalLogService) {
        val requestToken = globalLogRequests.begin(service)
        globalLogService = service
        globalLogs = null
        globalLogsLoading = true
        globalLogsError = null
        try {
            val loadedLogs = api.logs(service)
            if (globalLogRequests.isCurrent(requestToken, service) && globalLogService == service) {
                globalLogs = loadedLogs
            }
        } catch (failure: Throwable) {
            failure.rethrowIfCancellation()
            if (globalLogRequests.isCurrent(requestToken, service) && globalLogService == service) {
                globalLogsError = failure.userMessage("Server logs could not be loaded")
            }
        } finally {
            if (globalLogRequests.isCurrent(requestToken, service) && globalLogService == service) {
                globalLogsLoading = false
            }
        }
    }

    suspend fun refreshAccountLogs() {
        val target = selectedTarget ?: return
        val requestToken = accountLogRequests.begin(target)
        accountLogs = null
        accountLogsLoading = true
        accountLogsError = null
        try {
            val loadedLogs = api.accountLogs(target)
            if (accountLogRequests.isCurrent(requestToken, target) && selectedTarget == target) {
                accountLogs = loadedLogs
            }
        } catch (failure: Throwable) {
            failure.rethrowIfCancellation()
            if (accountLogRequests.isCurrent(requestToken, target) && selectedTarget == target) {
                accountLogsError = failure.userMessage("Account logs could not be loaded")
            }
        } finally {
            if (accountLogRequests.isCurrent(requestToken, target) && selectedTarget == target) {
                accountLogsLoading = false
            }
        }
    }

    suspend fun probeAuthentication(
        protocol: AuthenticationProtocol,
        credentialOverride: String?,
    ) {
        if (authenticationProbeLoading) return
        val target = selectedTarget ?: return
        authenticationProbe = null
        authenticationProbeError = null
        authenticationProbeLoading = true
        try {
            val result = api.probeAuthentication(
                AuthenticationProbeRequest(
                    address = target.address,
                    provider = target.provider,
                    protocol = protocol,
                    credentialOverride = credentialOverride,
                    providerAccountId = target.providerAccountId,
                ),
            ).redacted(credentialOverride)
            check(
                result.provider == target.provider &&
                    result.address.equals(target.address, ignoreCase = true) &&
                    result.protocol == protocol,
            ) {
                "Authentication probe response does not match the requested provider channel"
            }
            if (selectedTarget == target) {
                authenticationProbe = result
            }
        } catch (failure: Throwable) {
            failure.rethrowIfCancellation()
            if (selectedTarget == target) {
                authenticationProbeError = failure
                    .userMessage("Authentication probe failed")
                    .redactedEvidence(credentialOverride)
            }
        } finally {
            if (selectedTarget == target) {
                authenticationProbeLoading = false
            }
        }
    }

    suspend fun createAccount(request: CreateAccountRequest) = operation("Creating account") {
        val created = api.createAccount(request)
        lastReceipt = "${created.provider.displayName()} created ${created.address}"
        refreshAccounts(created.target())
    }

    suspend fun adoptPassword(password: String) = operation("Verifying existing password") {
        val target = requireNotNull(selectedTarget)
        lastReceipt = null
        val result = api.adoptPassword(target, AdoptPasswordRequest(password))
        if (!result.operation.success) {
            refreshAccounts(target)
            result.requireAchievedOperation()
        }
        applyAuthoritativeCredentialUpdate(target, result)
        result.requireAchievedOperation()
        lastReceipt = result.operation.message
        if (selectedTarget == target) refreshWorkspace()
    }

    suspend fun changePassword(newPassword: String) = operation("Changing password") {
        val target = requireNotNull(selectedTarget)
        lastReceipt = null
        val result = api.changePassword(target, ChangePasswordRequest(newPassword))
        if (!result.operation.success) {
            refreshAccounts(target)
            result.requireAchievedOperation()
        }
        applyAuthoritativeCredentialUpdate(target, result)
        result.requireAchievedOperation()
        lastReceipt = result.operation.message
        if (selectedTarget == target) refreshWorkspace()
    }

    suspend fun deleteSelectedAccount() = operation("Deleting account") {
        val target = requireNotNull(selectedTarget)
        val result = api.deleteAccount(target)
        lastReceipt = result.message
        selectedTarget = null
        refreshAccounts(null)
    }

    suspend fun createFolder(name: String) = operation("Creating folder") {
        requireMailActionsEnabled()
        val target = requireNotNull(selectedTarget)
        val created = api.createFolder(target, CreateFolderRequest(name))
        lastReceipt = "Folder created: ${created.name}"
        refreshWorkspace(keepFolderId = created.id, keepMessageId = null)
    }

    suspend fun deleteFolder(folderId: String) = operation("Deleting folder") {
        requireMailActionsEnabled()
        val target = requireNotNull(selectedTarget)
        val result = api.deleteFolder(target, folderId)
        lastReceipt = result.message
        refreshWorkspace(
            keepFolderId = selectedFolderId?.takeUnless { it == folderId },
            keepMessageId = null,
        )
    }

    suspend fun generateMessage(request: GenerateMessageRequest) = operation(request.deliveryMode.busyLabel()) {
        val targetAccount = accounts.firstOrNull(request::targetsExactly)
            ?: throw IllegalStateException("Target account is no longer available; refresh accounts")
        require(targetAccount.credentialReadiness == CredentialReadiness.READY) {
            "A ready provider credential is required to generate mail"
        }
        val result = api.generateMessage(request)
        lastReceipt = buildString {
            append(request.provider.displayName())
            append(" · ")
            append(request.deliveryMode.receiptLabel())
            append(" · ")
            append(result.operation.message)
            if (result.messageIds.isNotEmpty()) {
                append(" · IDs ")
                append(result.messageIds.joinToString())
            }
        }
        if (selectedTarget == targetAccount.target()) {
            refreshWorkspace(
                keepFolderId = when (request.deliveryMode) {
                    MessageDeliveryMode.DIRECT_APPEND -> request.folderId ?: selectedFolderId
                    MessageDeliveryMode.SMTP_DELIVERY -> null
                },
                keepMessageId = result.messageIds.lastOrNull(),
            )
        } else {
            refreshGlobalLogs()
        }
    }

    suspend fun mutateSelectedMessage(
        action: MessageAction,
        destinationFolderId: String? = null,
    ) = operation(action.busyLabel()) {
        requireMailActionsEnabled()
        val target = requireNotNull(selectedTarget)
        val summary = requireNotNull(selectedSummary)
        val mutationState = selectedMessage
            ?.takeIf { detail -> detail.id == summary.id && detail.folderId == summary.folderId }
            ?.mutationState
            ?: summary.mutationState
        val result = api.mutateMessages(
            target,
            MutateMessagesRequest(
                account = target.address,
                provider = target.provider,
                providerAccountId = target.providerAccountId,
                messageIds = listOf(summary.id),
                mutationStates = mapOf(summary.id to mutationState),
                action = action,
                sourceFolderId = summary.folderId,
                destinationFolderId = destinationFolderId,
            ),
        )
        lastReceipt = result.message
        val retainMessage = action in setOf(
            MessageAction.MARK_READ,
            MessageAction.MARK_UNREAD,
            MessageAction.FLAG,
            MessageAction.UNFLAG,
            MessageAction.COPY,
        )
        refreshWorkspace(
            keepFolderId = summary.folderId,
            keepMessageId = summary.id.takeIf { retainMessage },
        )
    }

    private suspend fun operation(label: String, block: suspend () -> Unit) {
        if (busyLabel != null) return
        busyLabel = label
        workspaceError = null
        operationError = null
        lastReceipt = null
        try {
            block()
        } catch (failure: Throwable) {
            failure.rethrowIfCancellation()
            operationError = failure.userMessage("$label failed")
        } finally {
            busyLabel = null
        }
    }

    private fun containsTarget(target: AccountTarget): Boolean =
        accounts.any { it.target() == target }

    /** The targeted credential endpoint response is the authoritative projection for this channel. */
    private fun applyAuthoritativeCredentialUpdate(
        target: AccountTarget,
        result: CredentialUpdateResponse,
    ) {
        check(
            result.provider == target.provider &&
                result.address.equals(target.address, ignoreCase = true) &&
                (!result.operation.success || result.readiness == CredentialReadiness.READY),
        ) {
            "Credential update response is inconsistent with the selected provider channel"
        }
        accounts = accounts.map { account ->
            if (account.target() == target) {
                account.copy(
                    credentialReadiness = result.readiness,
                    readinessMessage = result.operation.message.takeUnless { result.operation.success },
                    stale = false,
                )
            } else {
                account
            }
        }
    }

    private fun requireMailActionsEnabled(): AccountInfo = requireNotNull(selectedAccount) {
        "No account channel is selected"
    }.also { account ->
        require(account.credentialReadiness == CredentialReadiness.READY) {
            "A verified provider password is required for mail operations"
        }
    }

    private fun beginWorkspaceRequest(): Long {
        messageLoading = false
        return ++workspaceRequestGeneration
    }

    private fun isCurrentWorkspaceRequest(generation: Long, target: AccountTarget): Boolean =
        workspaceRequestGeneration == generation && selectedTarget == target

    private fun chooseFolder(availableFolders: List<FolderInfo>, preferredId: String?): FolderInfo? =
        availableFolders.firstOrNull { it.id == preferredId }
            ?: availableFolders.firstOrNull {
                it.id.equals("INBOX", ignoreCase = true) ||
                    it.name.equals("Inbox", ignoreCase = true)
            }
            ?: availableFolders.firstOrNull()

    private fun clearWorkspace() {
        accountLogRequests.invalidate()
        clearMailboxState()
        accountLogs = null
        accountLogsLoading = false
        accountLogsError = null
    }

    private fun clearMailboxState() {
        folders = emptyList()
        selectedFolderId = null
        messages = emptyList()
        selectedMessageId = null
        selectedMessage = null
        workspaceLoading = false
        messageLoading = false
    }

    private fun clearAuthenticationProbe() {
        authenticationProbe = null
        authenticationProbeLoading = false
        authenticationProbeError = null
    }
}

private fun AuthenticationProbeResponse.redacted(secret: String?): AuthenticationProbeResponse {
    return copy(
        providerResponse = providerResponse.redactedEvidence(secret),
        correlatedLogs = correlatedLogs
            .take(MAXIMUM_PROBE_LOG_LINES)
            .map { line -> line.redactedEvidence(secret) },
    )
}

private fun String.redactedEvidence(secret: String?): String {
    val withoutSecret = secret
        ?.takeIf(String::isNotEmpty)
        ?.let { replace(it, "[redacted]") }
        ?: this
    return withoutSecret
        .map { character -> if (character.isISOControl() && character != '\t') ' ' else character }
        .joinToString("")
        .trim()
        .take(MAXIMUM_PROBE_EVIDENCE_CHARACTERS)
}

private const val MAXIMUM_PROBE_EVIDENCE_CHARACTERS = 2_048
private const val MAXIMUM_PROBE_LOG_LINES = 200

private fun MessageDeliveryMode.busyLabel(): String = when (this) {
    MessageDeliveryMode.DIRECT_APPEND -> "Appending message directly"
    MessageDeliveryMode.SMTP_DELIVERY -> "Delivering message through SMTP"
}

private fun MessageDeliveryMode.receiptLabel(): String = when (this) {
    MessageDeliveryMode.DIRECT_APPEND -> "Direct append"
    MessageDeliveryMode.SMTP_DELIVERY -> "SMTP delivery"
}

private fun MessageAction.busyLabel(): String = when (this) {
    MessageAction.MARK_READ -> "Marking message read"
    MessageAction.MARK_UNREAD -> "Marking message unread"
    MessageAction.FLAG -> "Flagging message"
    MessageAction.UNFLAG -> "Removing message flag"
    MessageAction.MOVE -> "Moving message"
    MessageAction.COPY -> "Copying message"
    MessageAction.TRASH -> "Moving message to trash"
    MessageAction.DELETE -> "Deleting message"
}

private fun Throwable.userMessage(fallback: String): String =
    message?.takeIf(String::isNotBlank) ?: fallback

private fun Throwable.rethrowIfCancellation() {
    if (this is CancellationException) throw this
}
