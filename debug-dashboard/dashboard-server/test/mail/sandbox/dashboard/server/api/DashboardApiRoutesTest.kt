package mail.sandbox.dashboard.server.api

import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
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
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDetail
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageListResponse
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.MessageSummary
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.OperationResponse
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.contract.Routes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DashboardApiRoutesTest {
    @Test
    fun routesEveryDashboardOperationToTheInjectedBackend() {
        val backend = RecordingDashboardBackend()

        testApplication {
            application { routing { dashboardApiRoutes(backend) } }

            assertResponse(
                HttpStatusCode.OK,
                backend.accountList,
                client.get(Routes.ACCOUNTS),
            )
            assertResponse(
                HttpStatusCode.Created,
                backend.createdAccount,
                client.post(Routes.ACCOUNTS) { jsonBody(backend.createRequest) },
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.operation,
                client.delete(Routes.account(TEST_ADDRESS, Provider.STALWART)),
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.operation,
                client.put(Routes.accountPassword(TEST_ADDRESS, Provider.STALWART)) {
                    jsonBody(backend.passwordRequest)
                },
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.globalLogs,
                client.get("${Routes.LOGS}?service=stalwart"),
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.accountLogs,
                client.get(Routes.accountLogs(TEST_ADDRESS, Provider.STALWART)),
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.folderList,
                client.get(Routes.folders(TEST_ADDRESS, Provider.STALWART)),
            )
            assertResponse(
                HttpStatusCode.Created,
                backend.createdFolder,
                client.post(Routes.folders(TEST_ADDRESS, Provider.STALWART)) {
                    jsonBody(backend.folderRequest)
                },
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.operation,
                client.delete(Routes.folder(TEST_ADDRESS, Provider.STALWART, TEST_FOLDER_ID)),
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.messageList,
                client.get(
                    "${Routes.messages(TEST_ADDRESS, Provider.STALWART)}" +
                        "?folderId=$TEST_FOLDER_ID",
                ),
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.messageDetail,
                client.get(
                    "${Routes.message(TEST_ADDRESS, Provider.STALWART, TEST_MESSAGE_ID)}" +
                        "?folderId=$TEST_FOLDER_ID",
                ),
            )
            assertResponse(
                HttpStatusCode.OK,
                backend.operation,
                client.post(Routes.messageActions(TEST_ADDRESS, Provider.STALWART)) {
                    jsonBody(backend.mutationRequest)
                },
            )
            assertResponse(
                HttpStatusCode.Created,
                backend.generateResponse,
                client.post(Routes.GENERATE_MESSAGE) {
                    jsonBody(backend.generateRequest)
                },
            )
        }

        assertEquals(
            listOf(
                DashboardCall.ListAccounts,
                DashboardCall.CreateAccount(backend.createRequest),
                DashboardCall.DeleteAccount(TEST_ADDRESS, Provider.STALWART),
                DashboardCall.ChangePassword(
                    TEST_ADDRESS,
                    Provider.STALWART,
                    backend.passwordRequest,
                ),
                DashboardCall.Logs(LogService.STALWART),
                DashboardCall.AccountLogs(TEST_ADDRESS, Provider.STALWART),
                DashboardCall.ListFolders(TEST_ADDRESS, Provider.STALWART),
                DashboardCall.CreateFolder(
                    TEST_ADDRESS,
                    Provider.STALWART,
                    backend.folderRequest,
                ),
                DashboardCall.DeleteFolder(
                    TEST_ADDRESS,
                    Provider.STALWART,
                    TEST_FOLDER_ID,
                ),
                DashboardCall.ListMessages(
                    TEST_ADDRESS,
                    Provider.STALWART,
                    TEST_FOLDER_ID,
                ),
                DashboardCall.ReadMessage(
                    TEST_ADDRESS,
                    Provider.STALWART,
                    TEST_MESSAGE_ID,
                    TEST_FOLDER_ID,
                ),
                DashboardCall.MutateMessages(
                    TEST_ADDRESS,
                    Provider.STALWART,
                    backend.mutationRequest,
                ),
                DashboardCall.GenerateMessage(backend.generateRequest),
            ),
            backend.calls,
        )
    }

    @Test
    fun defaultsGlobalLogsToAllServicesAndAllowsMessageReadsWithoutAFolder() {
        val backend = RecordingDashboardBackend()

        testApplication {
            application { routing { dashboardApiRoutes(backend) } }

            assertEquals(HttpStatusCode.OK, client.get(Routes.LOGS).status)
            assertEquals(
                HttpStatusCode.OK,
                client.get(
                    Routes.message(TEST_ADDRESS, Provider.STALWART, TEST_MESSAGE_ID),
                ).status,
            )
        }

        assertEquals(
            listOf(
                DashboardCall.Logs(LogService.ALL),
                DashboardCall.ReadMessage(
                    TEST_ADDRESS,
                    Provider.STALWART,
                    TEST_MESSAGE_ID,
                    null,
                ),
            ),
            backend.calls,
        )
    }

    @Test
    fun rejectsMalformedJsonForEveryRequestBodyEndpoint() {
        val backend = RecordingDashboardBackend()

        testApplication {
            application { routing { dashboardApiRoutes(backend) } }

            listOf(
                client.post(Routes.ACCOUNTS) { malformedJsonBody() },
                client.put(Routes.accountPassword(TEST_ADDRESS, Provider.STALWART)) {
                    malformedJsonBody()
                },
                client.post(Routes.folders(TEST_ADDRESS, Provider.STALWART)) {
                    malformedJsonBody()
                },
                client.post(Routes.messageActions(TEST_ADDRESS, Provider.STALWART)) {
                    malformedJsonBody()
                },
                client.post(Routes.GENERATE_MESSAGE) { malformedJsonBody() },
            ).forEach { response ->
                assertEquals(HttpStatusCode.BadRequest, response.status)
                assertEquals(
                    DashboardApiError("bad_request", "Malformed JSON request"),
                    Json.decodeFromString<DashboardApiError>(response.bodyAsText()),
                )
            }
        }

        assertTrue(backend.calls.isEmpty())
    }

    @Test
    fun rejectsInvalidPathAndQueryEnumsAndMismatchedMutationTargets() {
        val backend = RecordingDashboardBackend()
        val mismatch = backend.mutationRequest.copy(account = "other@local.test")
        val missingSource = backend.mutationRequest.copy(sourceFolderId = null)
        val missingMutationState = backend.mutationRequest.copy(mutationStates = emptyMap())
        val batchMutation = backend.mutationRequest.copy(
            messageIds = listOf(TEST_MESSAGE_ID, "message-2"),
            mutationStates = mapOf(
                TEST_MESSAGE_ID to "email-state-7",
                "message-2" to "email-state-7",
            ),
        )
        val smtpWithFolder = backend.generateRequest.copy(
            deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
            folderId = TEST_FOLDER_ID,
        )
        val multipleMessages = backend.generateRequest.copy(count = 2)

        testApplication {
            application { routing { dashboardApiRoutes(backend) } }

            val invalidProvider = client.get(
                "/api/v1/accounts/$TEST_ADDRESS/providers/not-a-provider/folders",
            )
            val invalidService = client.get("${Routes.LOGS}?service=not-a-service")
            val mismatchedMutation = client.post(
                Routes.messageActions(TEST_ADDRESS, Provider.STALWART),
            ) {
                jsonBody(mismatch)
            }
            val missingSourceMutation = client.post(
                Routes.messageActions(TEST_ADDRESS, Provider.STALWART),
            ) {
                jsonBody(missingSource)
            }
            val missingStateMutation = client.post(
                Routes.messageActions(TEST_ADDRESS, Provider.STALWART),
            ) {
                jsonBody(missingMutationState)
            }
            val batchMessageMutation = client.post(
                Routes.messageActions(TEST_ADDRESS, Provider.STALWART),
            ) {
                jsonBody(batchMutation)
            }
            val invalidSmtpTarget = client.post(Routes.GENERATE_MESSAGE) {
                jsonBody(smtpWithFolder)
            }
            val multipleMessageGeneration = client.post(Routes.GENERATE_MESSAGE) {
                jsonBody(multipleMessages)
            }

            listOf(
                invalidProvider,
                invalidService,
                mismatchedMutation,
                missingSourceMutation,
                missingStateMutation,
                batchMessageMutation,
                invalidSmtpTarget,
                multipleMessageGeneration,
            ).forEach { response ->
                assertEquals(HttpStatusCode.BadRequest, response.status)
                assertEquals(
                    "bad_request",
                    Json.decodeFromString<DashboardApiError>(response.bodyAsText()).error,
                )
            }
        }

        assertTrue(backend.calls.isEmpty())
    }

    @Test
    fun mapsKnownMissingResourcesAndUnexpectedFailuresToTypedJsonErrors() {
        val backend = RecordingDashboardBackend()

        testApplication {
            application { routing { dashboardApiRoutes(backend) } }

            backend.failure = DashboardNotFoundException("Message does not exist")
            val missing = client.get(
                Routes.message(TEST_ADDRESS, Provider.STALWART, TEST_MESSAGE_ID),
            )
            assertEquals(HttpStatusCode.NotFound, missing.status)
            assertEquals(
                DashboardApiError("not_found", "Message does not exist"),
                Json.decodeFromString<DashboardApiError>(missing.bodyAsText()),
            )

            backend.failure = IllegalStateException("compose exploded")
            val failed = client.get(Routes.ACCOUNTS)
            assertEquals(HttpStatusCode.InternalServerError, failed.status)
            assertEquals(
                DashboardApiError("internal_error", "compose exploded"),
                Json.decodeFromString<DashboardApiError>(failed.bodyAsText()),
            )
        }
    }

    private suspend inline fun <reified T> assertResponse(
        expectedStatus: HttpStatusCode,
        expectedBody: T,
        response: io.ktor.client.statement.HttpResponse,
    ) {
        assertEquals(expectedStatus, response.status)
        assertEquals(
            ContentType.Application.Json.contentType,
            response.contentType()?.contentType,
        )
        assertEquals(expectedBody, Json.decodeFromString<T>(response.bodyAsText()))
    }

    private inline fun <reified T> io.ktor.client.request.HttpRequestBuilder.jsonBody(value: T) {
        contentType(ContentType.Application.Json)
        setBody(Json.encodeToString(value))
    }

    private fun io.ktor.client.request.HttpRequestBuilder.malformedJsonBody() {
        contentType(ContentType.Application.Json)
        setBody("{")
    }

}

private const val TEST_ADDRESS = "dev@local.test"
private const val TEST_FOLDER_ID = "inbox"
private const val TEST_MESSAGE_ID = "message-1"

private sealed interface DashboardCall {
    data object ListAccounts : DashboardCall
    data class CreateAccount(val request: CreateAccountRequest) : DashboardCall
    data class DeleteAccount(val address: String, val provider: Provider) : DashboardCall
    data class ChangePassword(
        val address: String,
        val provider: Provider,
        val request: ChangePasswordRequest,
    ) : DashboardCall
    data class Logs(val service: LogService) : DashboardCall
    data class AccountLogs(val address: String, val provider: Provider) : DashboardCall
    data class ListFolders(val address: String, val provider: Provider) : DashboardCall
    data class CreateFolder(
        val address: String,
        val provider: Provider,
        val request: CreateFolderRequest,
    ) : DashboardCall
    data class DeleteFolder(
        val address: String,
        val provider: Provider,
        val folderId: String,
    ) : DashboardCall
    data class ListMessages(
        val address: String,
        val provider: Provider,
        val folderId: String?,
    ) : DashboardCall
    data class ReadMessage(
        val address: String,
        val provider: Provider,
        val messageId: String,
        val folderId: String?,
    ) : DashboardCall
    data class MutateMessages(
        val address: String,
        val provider: Provider,
        val request: MutateMessagesRequest,
    ) : DashboardCall
    data class GenerateMessage(val request: GenerateMessageRequest) : DashboardCall
}

private class RecordingDashboardBackend : DashboardBackend {
    val createRequest = CreateAccountRequest(
        address = TEST_ADDRESS,
        password = "test-password",
        provider = Provider.STALWART,
        protocols = listOf(MailProtocol.IMAP, MailProtocol.JMAP, MailProtocol.SMTP),
    )
    val passwordRequest = ChangePasswordRequest("replacement-password")
    val folderRequest = CreateFolderRequest("Issues")
    val mutationRequest = MutateMessagesRequest(
        account = TEST_ADDRESS,
        provider = Provider.STALWART,
        messageIds = listOf(TEST_MESSAGE_ID),
        mutationStates = mapOf(TEST_MESSAGE_ID to "email-state-7"),
        action = MessageAction.MARK_READ,
        sourceFolderId = TEST_FOLDER_ID,
    )
    val generateRequest = GenerateMessageRequest(
        targetAccount = TEST_ADDRESS,
        provider = Provider.STALWART,
        sourceType = MessageSourceType.RANDOM,
        subject = "Generated reproduction",
        seed = 42,
    )
    val createdAccount = AccountInfo(
        address = TEST_ADDRESS,
        provider = Provider.STALWART,
        protocols = createRequest.protocols,
    )
    val accountList = AccountListResponse(listOf(createdAccount))
    val operation = OperationResponse(success = true, message = "done")
    val globalLogs = LogResponse(LogService.STALWART, lines = listOf("server ready"))
    val accountLogs = LogResponse(
        service = LogService.STALWART,
        account = TEST_ADDRESS,
        lines = listOf("authenticated"),
    )
    val createdFolder = FolderInfo("issues", "Issues", 0, 0)
    val folderList = FolderListResponse(listOf(createdFolder))
    val summary = MessageSummary(
        id = TEST_MESSAGE_ID,
        folderId = TEST_FOLDER_ID,
        mutationState = "email-state-7",
        subject = "A reproduction",
        fromAddress = "sender@local.test",
        receivedAt = "2026-08-05T12:00:00Z",
        isRead = false,
        isFlagged = false,
    )
    val messageList = MessageListResponse(listOf(summary))
    val messageDetail = MessageDetail(
        id = summary.id,
        folderId = summary.folderId,
        mutationState = "email-state-8",
        subject = summary.subject,
        fromAddress = summary.fromAddress,
        toAddresses = listOf(TEST_ADDRESS),
        sentAt = summary.receivedAt,
        textBody = "body",
        htmlBody = null,
        isRead = summary.isRead,
        isFlagged = summary.isFlagged,
    )
    val generateResponse = GenerateMessageResponse(
        messageIds = listOf("generated-1"),
        operation = operation,
    )
    val calls = mutableListOf<DashboardCall>()
    var failure: Throwable? = null

    override suspend fun listAccounts(): AccountListResponse = record(
        DashboardCall.ListAccounts,
        accountList,
    )

    override suspend fun createAccount(request: CreateAccountRequest): AccountInfo = record(
        DashboardCall.CreateAccount(request),
        createdAccount,
    )

    override suspend fun deleteAccount(
        address: String,
        provider: Provider,
    ): OperationResponse = record(
        DashboardCall.DeleteAccount(address, provider),
        operation,
    )

    override suspend fun changePassword(
        address: String,
        provider: Provider,
        request: ChangePasswordRequest,
    ): OperationResponse = record(
        DashboardCall.ChangePassword(address, provider, request),
        operation,
    )

    override suspend fun logs(service: LogService): LogResponse = record(
        DashboardCall.Logs(service),
        globalLogs,
    )

    override suspend fun accountLogs(
        address: String,
        provider: Provider,
    ): LogResponse = record(
        DashboardCall.AccountLogs(address, provider),
        accountLogs,
    )

    override suspend fun listFolders(
        address: String,
        provider: Provider,
    ): FolderListResponse = record(
        DashboardCall.ListFolders(address, provider),
        folderList,
    )

    override suspend fun createFolder(
        address: String,
        provider: Provider,
        request: CreateFolderRequest,
    ): FolderInfo = record(
        DashboardCall.CreateFolder(address, provider, request),
        createdFolder,
    )

    override suspend fun deleteFolder(
        address: String,
        provider: Provider,
        folderId: String,
    ): OperationResponse = record(
        DashboardCall.DeleteFolder(address, provider, folderId),
        operation,
    )

    override suspend fun listMessages(
        address: String,
        provider: Provider,
        folderId: String?,
    ): MessageListResponse = record(
        DashboardCall.ListMessages(address, provider, folderId),
        messageList,
    )

    override suspend fun readMessage(
        address: String,
        provider: Provider,
        messageId: String,
        folderId: String?,
    ): MessageDetail = record(
        DashboardCall.ReadMessage(address, provider, messageId, folderId),
        messageDetail,
    )

    override suspend fun mutateMessages(
        address: String,
        provider: Provider,
        request: MutateMessagesRequest,
    ): OperationResponse = record(
        DashboardCall.MutateMessages(address, provider, request),
        operation,
    )

    override suspend fun generateMessage(
        request: GenerateMessageRequest,
    ): GenerateMessageResponse = record(
        DashboardCall.GenerateMessage(request),
        generateResponse,
    )

    private fun <T> record(call: DashboardCall, result: T): T {
        failure?.let { throw it }
        calls += call
        return result
    }
}
