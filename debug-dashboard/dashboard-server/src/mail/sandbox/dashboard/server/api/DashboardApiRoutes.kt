package mail.sandbox.dashboard.server.api

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.put
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.ChangePasswordRequest
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.CreateFolderRequest
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.LogService
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.Routes

@Serializable
data class DashboardApiError(
    val error: String,
    val message: String,
)

internal fun Route.dashboardApiRoutes(backend: DashboardBackend) {
    get(Routes.ACCOUNTS) {
        call.respondFromBackend { backend.listAccounts() }
    }

    post(Routes.ACCOUNTS) {
        call.respondFromBackend(HttpStatusCode.Created) {
            backend.createAccount(decodeRequest<CreateAccountRequest>().validated())
        }
    }

    delete("${Routes.ACCOUNTS}/{address}/providers/{provider}") {
        call.respondFromBackend {
            val provider = requiredProvider()
            backend.deleteAccount(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
            )
        }
    }

    put("${Routes.ACCOUNTS}/{address}/providers/{provider}/password") {
        call.respondFromBackend {
            val provider = requiredProvider()
            backend.changePassword(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
                decodeRequest<ChangePasswordRequest>().validated(),
            )
        }
    }

    post("${Routes.ACCOUNTS}/{address}/providers/{provider}/password/verify") {
        call.respondFromBackend {
            val provider = requiredProvider()
            backend.adoptPassword(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
                decodeRequest<AdoptPasswordRequest>().validated(),
            )
        }
    }

    post(Routes.AUTHENTICATION_PROBES) {
        call.respondFromBackend {
            backend.probeAuthentication(
                decodeRequest<AuthenticationProbeRequest>().validated(),
            )
        }
    }

    get(Routes.LOGS) {
        call.respondFromBackend {
            backend.logs(optionalEnumQuery("service") ?: LogService.ALL)
        }
    }

    get("${Routes.LOGS}/accounts/{address}/providers/{provider}") {
        call.respondFromBackend {
            val provider = requiredProvider()
            backend.accountLogs(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
            )
        }
    }

    get("${Routes.ACCOUNTS}/{address}/providers/{provider}/folders") {
        call.respondFromBackend {
            val provider = requiredProvider()
            backend.listFolders(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
            )
        }
    }

    post("${Routes.ACCOUNTS}/{address}/providers/{provider}/folders") {
        call.respondFromBackend(HttpStatusCode.Created) {
            val provider = requiredProvider()
            backend.createFolder(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
                decodeRequest<CreateFolderRequest>().validated(),
            )
        }
    }

    delete("${Routes.ACCOUNTS}/{address}/providers/{provider}/folders/{folderId}") {
        call.respondFromBackend {
            val provider = requiredProvider()
            backend.deleteFolder(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
                requiredPath("folderId"),
            )
        }
    }

    get("${Routes.ACCOUNTS}/{address}/providers/{provider}/messages") {
        call.respondFromBackend {
            val provider = requiredProvider()
            backend.listMessages(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
                optionalQuery("folderId"),
            )
        }
    }

    get("${Routes.ACCOUNTS}/{address}/providers/{provider}/messages/{messageId}") {
        call.respondFromBackend {
            val provider = requiredProvider()
            backend.readMessage(
                requiredPath("address"),
                provider,
                requiredProviderAccountId(provider),
                requiredPath("messageId"),
                optionalQuery("folderId"),
            )
        }
    }

    post("${Routes.ACCOUNTS}/{address}/providers/{provider}/message-actions") {
        call.respondFromBackend {
            val address = requiredPath("address")
            val provider = requiredProvider()
            val providerAccountId = requiredProviderAccountId(provider)
            val request = decodeRequest<MutateMessagesRequest>().validated()
            if (
                request.account != address ||
                request.provider != provider ||
                request.providerAccountId != providerAccountId
            ) {
                throw DashboardBadRequestException(
                    "Message action target does not match the route",
                )
            }
            backend.mutateMessages(address, provider, providerAccountId, request)
        }
    }

    post(Routes.GENERATE_MESSAGE) {
        call.respondFromBackend(HttpStatusCode.Created) {
            backend.generateMessage(decodeRequest<GenerateMessageRequest>().validated())
        }
    }
}

private val dashboardJson = Json

private suspend inline fun <reified T> ApplicationCall.respondFromBackend(
    status: HttpStatusCode = HttpStatusCode.OK,
    action: suspend ApplicationCall.() -> T,
) {
    try {
        respondJson(action(), status)
    } catch (cancellation: CancellationException) {
        throw cancellation
    } catch (error: DashboardNotFoundException) {
        respondError(
            HttpStatusCode.NotFound,
            "not_found",
            error.message ?: "Resource not found",
        )
    } catch (error: IllegalArgumentException) {
        respondError(
            HttpStatusCode.BadRequest,
            "bad_request",
            error.message ?: "Invalid request",
        )
    } catch (error: Exception) {
        respondError(
            HttpStatusCode.InternalServerError,
            "internal_error",
            error.message ?: "Dashboard operation failed",
        )
    }
}

private suspend inline fun <reified T> ApplicationCall.decodeRequest(): T {
    val body = receiveText()
    return try {
        dashboardJson.decodeFromString<T>(body)
    } catch (_: SerializationException) {
        throw DashboardBadRequestException("Malformed JSON request")
    } catch (_: IllegalArgumentException) {
        throw DashboardBadRequestException("Malformed JSON request")
    }
}

private fun ApplicationCall.requiredPath(name: String): String =
    parameters[name]?.takeIf(String::isNotBlank)
        ?: throw DashboardBadRequestException("Missing path parameter: $name")

private fun ApplicationCall.requiredProvider(): Provider {
    val value = requiredPath("provider")
    return Provider.entries.firstOrNull { it.name.equals(value, ignoreCase = true) }
        ?: throw DashboardBadRequestException("Unknown provider: $value")
}

private fun ApplicationCall.requiredProviderAccountId(provider: Provider): String? {
    val accountId = optionalQuery("providerAccountId")
    return when (provider) {
        Provider.DOVECOT -> {
            require(accountId == null) { "Dovecot accounts do not use a provider Account ID" }
            null
        }
        Provider.STALWART -> accountId
            ?: throw DashboardBadRequestException(
                "Stalwart provider Account ID is required; refresh the account list",
            )
    }
}

private inline fun <reified T : Enum<T>> ApplicationCall.optionalEnumQuery(name: String): T? {
    val value = request.queryParameters[name] ?: return null
    if (value.isBlank()) {
        throw DashboardBadRequestException("Empty query parameter: $name")
    }
    return enumValues<T>().firstOrNull { it.name.equals(value, ignoreCase = true) }
        ?: throw DashboardBadRequestException("Unknown $name: $value")
}

private fun ApplicationCall.optionalQuery(name: String): String? {
    val value = request.queryParameters[name] ?: return null
    return value.takeIf(String::isNotBlank)
        ?: throw DashboardBadRequestException("Empty query parameter: $name")
}

private suspend inline fun <reified T> ApplicationCall.respondJson(
    value: T,
    status: HttpStatusCode,
) {
    respondText(
        text = dashboardJson.encodeToString(value),
        contentType = ContentType.Application.Json,
        status = status,
    )
}

private suspend fun ApplicationCall.respondError(
    status: HttpStatusCode,
    code: String,
    message: String,
) {
    respondJson(DashboardApiError(code, message), status)
}

private fun CreateAccountRequest.validated(): CreateAccountRequest {
    require(address.isNotBlank()) { "Account address is required" }
    password.requirePassword("Account password")
    require(protocols.isNotEmpty()) { "At least one protocol is required" }
    return this
}

private fun ChangePasswordRequest.validated(): ChangePasswordRequest {
    newPassword.requirePassword("New password")
    return this
}

private fun AdoptPasswordRequest.validated(): AdoptPasswordRequest {
    password.requirePassword("Account password")
    return this
}

private fun AuthenticationProbeRequest.validated(): AuthenticationProbeRequest {
    require(address.isNotBlank()) { "Account address is required" }
    requireProviderIdentity(provider, providerAccountId)
    credentialOverride?.requireBoundedSecret("Credential override", allowBlank = true)
    if (
        protocol == AuthenticationProtocol.OAUTH_IMAP ||
        protocol == AuthenticationProtocol.OAUTH_SMTP
    ) {
        require(credentialOverride != null) { "OAuth probes require a credential override" }
    }
    val supported = when (provider) {
        Provider.DOVECOT -> setOf(
            AuthenticationProtocol.IMAP,
            AuthenticationProtocol.POP3,
            AuthenticationProtocol.SMTP,
            AuthenticationProtocol.OAUTH_IMAP,
            AuthenticationProtocol.OAUTH_SMTP,
        )
        Provider.STALWART -> setOf(
            AuthenticationProtocol.JMAP,
            AuthenticationProtocol.SMTP,
        )
    }
    require(protocol in supported) {
        "$protocol authentication probes are not supported by $provider"
    }
    return this
}

private fun String.requirePassword(label: String) {
    requireBoundedSecret(label, allowBlank = false)
}

private fun String.requireBoundedSecret(label: String, allowBlank: Boolean) {
    if (!allowBlank) require(isNotBlank()) { "$label is required" }
    require(length <= MAX_CREDENTIAL_LENGTH) { "$label is too large" }
    require(none { it == '\u0000' || it == '\r' || it == '\n' }) {
        "$label contains an unsupported delimiter"
    }
}

private fun CreateFolderRequest.validated(): CreateFolderRequest {
    require(name.isNotBlank()) { "Folder name is required" }
    return this
}

private fun MutateMessagesRequest.validated(): MutateMessagesRequest {
    require(account.isNotBlank()) { "Account is required" }
    requireProviderIdentity(provider, providerAccountId)
    require(messageIds.isNotEmpty() && messageIds.none(String::isBlank)) {
        "At least one message is required"
    }
    require(messageIds.size == 1) {
        "Message operations act on exactly one message"
    }
    require(messageIds.distinct().size == messageIds.size) {
        "Message IDs must be unique"
    }
    require(
        mutationStates.keys == messageIds.toSet() &&
            mutationStates.values.none(String::isBlank),
    ) {
        "Every message requires its mutation state"
    }
    require(mutationStates.values.distinct().size == 1) {
        "Messages from different states must be refreshed before mutation"
    }
    require(sourceFolderId?.isNotBlank() == true) {
        "A source folder is required for message operations"
    }
    if (action == MessageAction.MOVE || action == MessageAction.COPY) {
        require(destinationFolderId?.isNotBlank() == true) {
            "A destination folder is required for $action"
        }
    }
    return this
}

private fun GenerateMessageRequest.validated(): GenerateMessageRequest {
    require(targetAccount.isNotBlank()) { "Target account is required" }
    requireProviderIdentity(provider, providerAccountId)
    require(count == 1) { "Exactly one message is required" }
    if (deliveryMode == MessageDeliveryMode.SMTP_DELIVERY) {
        require(folderId == null) { "SMTP delivery always targets the Inbox" }
    }
    return this
}

private fun requireProviderIdentity(provider: Provider, providerAccountId: String?) {
    when (provider) {
        Provider.DOVECOT -> require(providerAccountId == null) {
            "Dovecot accounts do not use a provider Account ID"
        }
        Provider.STALWART -> require(!providerAccountId.isNullOrBlank()) {
            "Stalwart provider Account ID is required; refresh the account list"
        }
    }
}

private const val MAX_CREDENTIAL_LENGTH = 4_096
