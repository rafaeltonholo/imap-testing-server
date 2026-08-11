package mail.sandbox.dashboard.server.provider.stalwart.product

import java.net.URI
import java.time.Instant
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import mail.sandbox.dashboard.server.gate.stalwart.DASHBOARD_MAIL_PERMISSIONS
import mail.sandbox.dashboard.server.gate.stalwart.GateCredential
import mail.sandbox.dashboard.server.gate.stalwart.GateHttpTransport
import mail.sandbox.dashboard.server.gate.stalwart.GateJmapCapability
import mail.sandbox.dashboard.server.gate.stalwart.GateJmapClient
import mail.sandbox.dashboard.server.gate.stalwart.KtorGateHttpTransport

private data class FetchedEmails(
    val state: String,
    val emails: List<JsonObject>,
)

/**
 * Local developer-tool adapter for the Stalwart v0.16 JMAP and registry APIs.
 * Ownership of [transport] transfers to the adapter when it is closeable.
 */
internal class StalwartProductAdapter(
    private val baseUri: URI,
    private val managementCredentialProvider: StalwartManagementCredentialProvider,
    private val accountCredentialCatalog: StalwartAccountCredentialCatalog,
    private val transport: GateHttpTransport,
) : AutoCloseable {
    constructor(
        baseUri: URI,
        managementCredentialProvider: StalwartManagementCredentialProvider,
        accountCredentialCatalog: StalwartAccountCredentialCatalog,
    ) : this(
        baseUri = baseUri,
        managementCredentialProvider = managementCredentialProvider,
        accountCredentialCatalog = accountCredentialCatalog,
        transport = KtorGateHttpTransport(),
    )

    suspend fun listAccounts(): List<StalwartProductAccount> =
        withManagementClient { client, managementAccountId ->
            val accounts = registryObjects(
                client = client,
                managementAccountId = managementAccountId,
                objectType = ACCOUNT_OBJECT,
            ).filter { account ->
                account.optionalString("@type") == "User"
            }
            val domainIds = accounts.map { it.requiredString("domainId") }.distinct()
            val domains = registryGetObjects(
                client = client,
                managementAccountId = managementAccountId,
                objectType = DOMAIN_OBJECT,
                ids = domainIds,
            ).associate { domain ->
                domain.requiredString("id") to domain.requiredString("name")
            }
            accounts.mapNotNull { account ->
                val id = account.requiredString("id")
                val domain = domains[account.requiredString("domainId")]
                    ?: malformed("Account referenced an absent Domain")
                val address = "${account.requiredString("name")}@$domain"
                if (address.equals(MANAGEMENT_ADDRESS, ignoreCase = true)) {
                    return@mapNotNull null
                }
                StalwartProductAccount(
                    id = id,
                    address = address,
                    enabledProtocols = account.enabledProtocols(),
                )
            }.sortedBy(StalwartProductAccount::address)
        }

    suspend fun createAccount(request: StalwartCreateAccount): StalwartProductAccount {
        val address = parseAddress(request.address)
        requirePassword(request.password, "Account password")
        require(request.enabledProtocols.isNotEmpty()) {
            "At least one Account protocol must be enabled"
        }
        require(StalwartProductProtocol.IMAP !in request.enabledProtocols) {
            "Stalwart IMAP is not published by this local fixture"
        }
        val accountId = withManagementClient { client, managementAccountId ->
            val domain = registryObjects(
                client = client,
                managementAccountId = managementAccountId,
                objectType = DOMAIN_OBJECT,
            ).singleOrNull { candidate ->
                candidate.requiredString("name").equals(address.domain, ignoreCase = true)
            } ?: throw StalwartProductException(
                "Stalwart Domain '${address.domain}' is not registered",
            )
            val response = client.registryCreate(
                objectType = ACCOUNT_OBJECT,
                creationId = ACCOUNT_CREATION_ID,
                accountId = managementAccountId,
                value = buildJsonObject {
                    put("@type", "User")
                    put("name", address.localPart)
                    put("domainId", domain.requiredString("id"))
                    put(
                        "credentials",
                        buildJsonObject {
                            put(
                                "0",
                                buildJsonObject {
                                    put("@type", "Password")
                                    put("secret", request.password)
                                    put("allowedIps", buildJsonObject {})
                                },
                            )
                        },
                    )
                    put("roles", typed("User"))
                    put("permissions", permissions(request.enabledProtocols))
                },
            )
            requireCreatedId(
                response = response,
                expectedMethod = "x:Account/set",
                expectedAccountId = managementAccountId,
                creationId = ACCOUNT_CREATION_ID,
            )
        }
        return StalwartProductAccount(
            id = accountId,
            address = request.address,
            enabledProtocols = request.enabledProtocols,
        )
    }

    suspend fun changePassword(accountId: String, newPassword: String) {
        require(accountId.isNotBlank()) { "Account ID is absent" }
        requirePassword(newPassword, "New password")
        if (accountCredentialCatalog.find(accountId) == null) {
            throw StalwartProductException(
                "No local credential is registered for the Stalwart Account",
            )
        }
        withManagementClient { client, managementAccountId ->
            val account = registryGetObjects(
                client = client,
                managementAccountId = managementAccountId,
                objectType = ACCOUNT_OBJECT,
                ids = listOf(accountId),
            ).singleOrNull()
                ?: throw StalwartProductException("Stalwart Account was not found")
            val passwordKey = account.requiredObject("credentials")
                .entries
                .singleOrNull { (_, credential) ->
                    (credential as? JsonObject)?.optionalString("@type") == "Password"
                }
                ?.key
                ?: throw StalwartProductException(
                    "Stalwart Account has no mutable Password credential",
                )
            val response = client.registryUpdate(
                objectType = ACCOUNT_OBJECT,
                objectId = accountId,
                patch = buildJsonObject {
                    put("credentials/$passwordKey/secret", newPassword)
                },
                accountId = managementAccountId,
            )
            requireUpdated(
                response = response,
                expectedMethod = "x:Account/set",
                expectedAccountId = managementAccountId,
                objectId = accountId,
            )
        }
    }

    suspend fun deleteAccount(accountId: String) {
        require(accountId.isNotBlank()) { "Account ID is absent" }
        withManagementClient { client, managementAccountId ->
            val response = client.registryDestroy(
                objectType = ACCOUNT_OBJECT,
                objectId = accountId,
                accountId = managementAccountId,
            )
            requireDestroyed(
                response = response,
                expectedMethod = "x:Account/set",
                expectedAccountId = managementAccountId,
                objectId = accountId,
            )
        }
        accountCredentialCatalog.remove(accountId)
    }

    suspend fun listFolders(accountId: String): List<StalwartProductFolder> =
        withAccountClient(accountId) { client ->
            val payload = callPayload(
                client = client,
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ids", JsonNull)
                    put(
                        "properties",
                        strings(
                            "id",
                            "name",
                            "role",
                            "parentId",
                            "totalEmails",
                            "unreadEmails",
                        ),
                    )
                },
            )
            requireAccount(payload, accountId)
            payload.requiredArray("list").map { value ->
                val mailbox = value.requiredObjectValue("Mailbox")
                StalwartProductFolder(
                    id = mailbox.requiredString("id"),
                    name = mailbox.requiredString("name"),
                    role = mailbox.optionalString("role"),
                    parentId = mailbox.optionalString("parentId"),
                    totalEmails = mailbox.optionalInt("totalEmails") ?: 0,
                    unreadEmails = mailbox.optionalInt("unreadEmails") ?: 0,
                )
            }.sortedWith(compareBy({ it.role != "inbox" }, StalwartProductFolder::name))
        }

    suspend fun createFolder(
        accountId: String,
        name: String,
        parentId: String? = null,
    ): StalwartProductFolder {
        require(name.isNotBlank()) { "Mailbox name is absent" }
        val id = withAccountClient(accountId) { client ->
            val response = client.call(
                methodName = "Mailbox/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                MAILBOX_CREATION_ID,
                                buildJsonObject {
                                    put("name", name)
                                    put("parentId", parentId?.let(::JsonPrimitive) ?: JsonNull)
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
            requireCreatedId(
                response = response,
                expectedMethod = "Mailbox/set",
                expectedAccountId = accountId,
                creationId = MAILBOX_CREATION_ID,
            )
        }
        return StalwartProductFolder(id, name, null, parentId, 0, 0)
    }

    suspend fun deleteFolder(accountId: String, folderId: String) {
        withAccountClient(accountId) { client ->
            val response = client.call(
                methodName = "Mailbox/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("destroy", strings(folderId))
                },
                capabilities = MAIL_CAPABILITIES,
            )
            requireDestroyed(response, "Mailbox/set", accountId, folderId)
        }
    }

    suspend fun listMessages(
        accountId: String,
        mailboxId: String? = null,
        limit: Int = 100,
    ): List<StalwartProductMessageSummary> {
        require(limit in 1..100) { "Message list limit must be between 1 and 100" }
        return withAccountClient(accountId) { client ->
            val ids = mutableListOf<String>()
            val seenIds = hashSetOf<String>()
            var queryState: String? = null
            var position = 0
            while (true) {
                val query = callPayload(
                    client = client,
                    methodName = "Email/query",
                    arguments = buildJsonObject {
                        put("accountId", accountId)
                        put(
                            "filter",
                            buildJsonObject {
                                mailboxId?.let { put("inMailbox", it) }
                            },
                        )
                        put(
                            "sort",
                            buildJsonArray {
                                add(
                                    buildJsonObject {
                                        put("property", "receivedAt")
                                        put("isAscending", false)
                                    },
                                )
                            },
                        )
                        put("position", position)
                        put("limit", limit)
                        put("calculateTotal", true)
                    },
                )
                requireAccount(query, accountId)
                val pageQueryState = query.requiredString("queryState")
                if (queryState == null) {
                    queryState = pageQueryState
                } else if (queryState != pageQueryState) {
                    malformed("Stalwart Email query changed during pagination")
                }
                val page = query.requiredArray("ids")
                    .map { it.requiredStringValue("Email ID") }
                page.forEach { emailId ->
                    if (!seenIds.add(emailId)) {
                        malformed("Stalwart Email query returned duplicate Email IDs")
                    }
                }
                val total = query.requiredInt("total")
                ids += page
                if (ids.size >= total) break
                if (page.isEmpty()) malformed("Email query made no progress")
                position += page.size
            }
            if (ids.isEmpty()) {
                emptyList()
            } else {
                ids.chunked(limit).flatMap { page ->
                    val fetched = fetchEmails(client, accountId, page, includeBodies = false)
                    fetched.emails.map { email -> decodeSummary(email, fetched.state) }
                }
            }
        }
    }

    suspend fun readMessage(
        accountId: String,
        emailId: String,
    ): StalwartProductMessage = withAccountClient(accountId) { client ->
        val fetched = fetchEmails(
            client = client,
            accountId = accountId,
            ids = listOf(emailId),
            includeBodies = true,
        )
        val email = fetched.emails.singleOrNull()
            ?: throw StalwartProductException("Stalwart Email was not found")
        val bodyValues = email.requiredObject("bodyValues")
        StalwartProductMessage(
            summary = decodeSummary(email, fetched.state),
            recipients = email.addresses("to"),
            textBody = email.firstBodyValue("textBody", bodyValues),
            htmlBody = email.firstBodyValue("htmlBody", bodyValues),
        )
    }

    suspend fun importEml(
        accountId: String,
        mailboxId: String,
        rawEml: String,
        receivedAt: Instant = Instant.now(),
    ): StalwartImportedEmail {
        require(rawEml.isNotBlank()) { "Raw EML is absent" }
        return withAccountClient(accountId) { client ->
            val blobResponse = client.call(
                methodName = "Blob/upload",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                BLOB_CREATION_ID,
                                buildJsonObject {
                                    put(
                                        "data",
                                        buildJsonArray {
                                            add(buildJsonObject { put("data:asText", rawEml) })
                                        },
                                    )
                                    put("type", "message/rfc822")
                                },
                            )
                        },
                    )
                },
                capabilities = BLOB_CAPABILITIES,
            )
            val blobId = requireCreatedId(
                response = blobResponse,
                expectedMethod = "Blob/upload",
                expectedAccountId = accountId,
                creationId = BLOB_CREATION_ID,
            )
            val importResponse = client.call(
                methodName = "Email/import",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put(
                        "emails",
                        buildJsonObject {
                            put(
                                EMAIL_CREATION_ID,
                                buildJsonObject {
                                    put("blobId", blobId)
                                    put("mailboxIds", buildJsonObject { put(mailboxId, true) })
                                    put("keywords", buildJsonObject {})
                                    put("receivedAt", receivedAt.toString())
                                },
                            )
                        },
                    )
                },
                capabilities = BLOB_CAPABILITIES,
            )
            val emailId = requireCreatedId(
                response = importResponse,
                expectedMethod = "Email/import",
                expectedAccountId = accountId,
                creationId = EMAIL_CREATION_ID,
            )
            StalwartImportedEmail(emailId = emailId, blobId = blobId)
        }
    }

    suspend fun setSeen(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        seen: Boolean,
    ) {
        updateEmails(accountId, emailIds, expectedState) {
            put("keywords/\$seen", if (seen) JsonPrimitive(true) else JsonNull)
        }
    }

    suspend fun setFlagged(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        flagged: Boolean,
    ) {
        updateEmails(accountId, emailIds, expectedState) {
            put("keywords/\$flagged", if (flagged) JsonPrimitive(true) else JsonNull)
        }
    }

    suspend fun moveMessages(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        sourceMailboxId: String,
        targetMailboxId: String,
    ) {
        updateEmails(accountId, emailIds, expectedState) {
            put("mailboxIds/$sourceMailboxId", JsonNull)
            put("mailboxIds/$targetMailboxId", true)
        }
    }

    suspend fun copyMessages(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        targetMailboxId: String,
    ): List<String> {
        updateEmails(accountId, emailIds, expectedState) {
            put("mailboxIds/$targetMailboxId", true)
        }
        return emailIds
    }

    suspend fun trashMessages(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        sourceMailboxId: String,
    ) {
        val trash = listFolders(accountId).singleOrNull { it.role == "trash" }
            ?: throw StalwartProductException("Stalwart Account has no Trash mailbox")
        moveMessages(accountId, emailIds, expectedState, sourceMailboxId, trash.id)
    }

    suspend fun deleteMessages(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
    ) {
        requireMutationArguments(emailIds, expectedState)
        withAccountClient(accountId) { client ->
            val response = client.call(
                methodName = "Email/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ifInState", expectedState)
                    put("destroy", JsonArray(emailIds.map(::JsonPrimitive)))
                },
                capabilities = MAIL_CAPABILITIES,
            )
            requireDestroyed(response, "Email/set", accountId, emailIds)
        }
    }

    private suspend fun updateEmails(
        accountId: String,
        emailIds: List<String>,
        expectedState: String,
        patch: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit,
    ) {
        requireMutationArguments(emailIds, expectedState)
        withAccountClient(accountId) { client ->
            val response = client.call(
                methodName = "Email/set",
                arguments = buildJsonObject {
                    put("accountId", accountId)
                    put("ifInState", expectedState)
                    put(
                        "update",
                        buildJsonObject {
                            emailIds.forEach { emailId ->
                                put(emailId, buildJsonObject(patch))
                            }
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            )
            requireUpdated(response, "Email/set", accountId, emailIds)
        }
    }

    private fun requireMutationArguments(emailIds: List<String>, expectedState: String) {
        require(
            emailIds.isNotEmpty() &&
                emailIds.none(String::isBlank) &&
                emailIds.distinct().size == emailIds.size,
        ) { "Stalwart Email IDs are invalid" }
        require(expectedState.isNotBlank()) { "Stalwart Email state is invalid" }
    }

    private suspend fun fetchEmails(
        client: GateJmapClient,
        accountId: String,
        ids: List<String>,
        includeBodies: Boolean,
    ): FetchedEmails {
        val properties = mutableListOf(
            "id",
            "subject",
            "from",
            "receivedAt",
            "preview",
            "mailboxIds",
            "keywords",
            "messageId",
        )
        if (includeBodies) {
            properties += listOf("to", "textBody", "htmlBody", "bodyValues")
        }
        val payload = callPayload(
            client = client,
            methodName = "Email/get",
            arguments = buildJsonObject {
                put("accountId", accountId)
                put("ids", JsonArray(ids.map(::JsonPrimitive)))
                put("properties", JsonArray(properties.map(::JsonPrimitive)))
                if (includeBodies) {
                    put("fetchTextBodyValues", true)
                    put("fetchHTMLBodyValues", true)
                }
            },
        )
        requireAccount(payload, accountId)
        return FetchedEmails(
            state = payload.requiredString("state"),
            emails = payload.requiredArray("list").map { it.requiredObjectValue("Email") },
        )
    }

    private fun decodeSummary(email: JsonObject, state: String): StalwartProductMessageSummary =
        StalwartProductMessageSummary(
            id = email.requiredString("id"),
            state = state,
            subject = email.optionalString("subject").orEmpty(),
            sender = email.addresses("from").firstOrNull(),
            receivedAt = email.optionalString("receivedAt"),
            preview = email.optionalString("preview").orEmpty(),
            mailboxIds = email.trueMapKeys("mailboxIds"),
            seen = "\$seen" in email.trueMapKeys("keywords"),
            flagged = "\$flagged" in email.trueMapKeys("keywords"),
            messageIds = email.optionalStringArray("messageId"),
        )

    private suspend fun callPayload(
        client: GateJmapClient,
        methodName: String,
        arguments: JsonObject,
    ): JsonObject = methodPayload(
        response = client.call(
            methodName = methodName,
            arguments = arguments,
            capabilities = MAIL_CAPABILITIES,
        ),
        expectedMethod = methodName,
    )

    private suspend fun registryObjects(
        client: GateJmapClient,
        managementAccountId: String,
        objectType: String,
    ): List<JsonObject> {
        val ids = mutableListOf<String>()
        var position = 0
        while (true) {
            val payload = methodPayload(
                response = client.registryQuery(
                    objectType = objectType,
                    accountId = managementAccountId,
                    position = position,
                    limit = REGISTRY_PAGE_SIZE,
                ),
                expectedMethod = "x:$objectType/query",
            )
            requireAccount(payload, managementAccountId)
            val page = payload.requiredArray("ids")
                .map { it.requiredStringValue("$objectType ID") }
            val total = payload.requiredInt("total")
            ids += page
            if (ids.size >= total) break
            if (page.isEmpty()) malformed("$objectType query made no progress")
            position += page.size
        }
        return registryGetObjects(
            client = client,
            managementAccountId = managementAccountId,
            objectType = objectType,
            ids = ids,
        )
    }

    private suspend fun registryGetObjects(
        client: GateJmapClient,
        managementAccountId: String,
        objectType: String,
        ids: List<String>,
    ): List<JsonObject> {
        if (ids.isEmpty()) return emptyList()
        return ids.chunked(REGISTRY_PAGE_SIZE).flatMap { page ->
            val payload = methodPayload(
                response = client.registryGet(
                    objectType = objectType,
                    ids = page,
                    accountId = managementAccountId,
                ),
                expectedMethod = "x:$objectType/get",
            )
            requireAccount(payload, managementAccountId)
            if (payload.requiredArray("notFound").isNotEmpty()) {
                malformed("$objectType/get reported missing registry objects")
            }
            payload.requiredArray("list").map { it.requiredObjectValue(objectType) }
        }
    }

    private suspend fun <T> withManagementClient(
        block: suspend (GateJmapClient, String) -> T,
    ): T {
        val credential = managementCredentialProvider.openCredential()
        return GateJmapClient(baseUri, credential, transport).use { client ->
            val managementAccountId = client.discoverSession().primaryAccountId
                ?: malformed("Management JMAP Session omitted its primary Account")
            block(client, managementAccountId)
        }
    }

    private suspend fun <T> withAccountClient(
        accountId: String,
        block: suspend (GateJmapClient) -> T,
    ): T {
        val login = accountCredentialCatalog.find(accountId)
            ?: throw StalwartProductException(
                "No local credential is registered for the Stalwart Account",
            )
        val credential = GateCredential.basic(login.address, login.password.toCharArray())
        return GateJmapClient(baseUri, credential, transport).use { client ->
            val session = client.discoverSession()
            if (session.primaryAccountId != accountId) {
                malformed("Account JMAP Session resolved another primary Account")
            }
            block(client)
        }
    }

    override fun close() {
        (transport as? AutoCloseable)?.close()
    }

    private companion object {
        const val ACCOUNT_OBJECT = "Account"
        const val DOMAIN_OBJECT = "Domain"
        const val ACCOUNT_CREATION_ID = "dashboard-account"
        const val MAILBOX_CREATION_ID = "dashboard-mailbox"
        const val BLOB_CREATION_ID = "dashboard-blob"
        const val EMAIL_CREATION_ID = "dashboard-email"
        const val REGISTRY_PAGE_SIZE = 100
        const val MANAGEMENT_ADDRESS = "dashboard-management@local.test"

        val MAIL_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.MAIL,
        )
        val BLOB_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.MAIL,
            GateJmapCapability.BLOB,
        )

        fun permissions(protocols: Set<StalwartProductProtocol>): JsonObject {
            // Dashboard CRUD always uses JMAP internally, even when the account's
            // advertised client protocol selection is SMTP-only.
            val enabled = linkedSetOf("authenticate", "emailReceive")
            enabled += DASHBOARD_MAIL_PERMISSIONS
            if (StalwartProductProtocol.SMTP in protocols) {
                enabled += setOf("emailSend", "emailReceive")
            }
            return buildJsonObject {
                put("@type", "Replace")
                put(
                    "enabledPermissions",
                    buildJsonObject {
                        enabled.forEach { permission -> put(permission, true) }
                    },
                )
                put("disabledPermissions", buildJsonObject {})
            }
        }

        fun typed(type: String): JsonObject = buildJsonObject { put("@type", type) }

        fun strings(vararg values: String): JsonArray =
            JsonArray(values.map(::JsonPrimitive))

        fun methodPayload(response: JsonObject, expectedMethod: String): JsonObject {
            val tuple = response.requiredArray("methodResponses").singleOrNull()
                as? JsonArray ?: malformed("JMAP response did not contain one method")
            if (tuple.size != 3 || tuple[0].requiredStringValue("method") != expectedMethod) {
                malformed("JMAP response method did not match the request")
            }
            return tuple[1].requiredObjectValue("JMAP method payload")
        }

        fun requireCreatedId(
            response: JsonObject,
            expectedMethod: String,
            expectedAccountId: String,
            creationId: String,
        ): String {
            val payload = methodPayload(response, expectedMethod)
            requireAccount(payload, expectedAccountId)
            if (payload.optionalObject("notCreated")?.isNotEmpty() == true) {
                throw StalwartProductException("$expectedMethod rejected the create operation")
            }
            return payload.requiredObject("created")
                .requiredObject(creationId)
                .requiredString("id")
        }

        fun requireUpdated(
            response: JsonObject,
            expectedMethod: String,
            expectedAccountId: String,
            objectId: String,
        ) = requireUpdated(response, expectedMethod, expectedAccountId, listOf(objectId))

        fun requireUpdated(
            response: JsonObject,
            expectedMethod: String,
            expectedAccountId: String,
            objectIds: List<String>,
        ) {
            val payload = methodPayload(response, expectedMethod)
            requireAccount(payload, expectedAccountId)
            if (payload.optionalObject("notUpdated")?.isNotEmpty() == true) {
                throw StalwartProductException("$expectedMethod rejected the update operation")
            }
            if (payload.requiredObject("updated").keys != objectIds.toSet()) {
                malformed("$expectedMethod did not confirm the updated objects")
            }
        }

        fun requireDestroyed(
            response: JsonObject,
            expectedMethod: String,
            expectedAccountId: String,
            objectId: String,
        ) = requireDestroyed(response, expectedMethod, expectedAccountId, listOf(objectId))

        fun requireDestroyed(
            response: JsonObject,
            expectedMethod: String,
            expectedAccountId: String,
            objectIds: List<String>,
        ) {
            val payload = methodPayload(response, expectedMethod)
            requireAccount(payload, expectedAccountId)
            if (payload.optionalObject("notDestroyed")?.isNotEmpty() == true) {
                throw StalwartProductException("$expectedMethod rejected the delete operation")
            }
            val destroyed = payload.requiredArray("destroyed").map {
                    it.requiredStringValue("destroyed ID")
                }
            if (destroyed.size != objectIds.size || destroyed.toSet() != objectIds.toSet()) {
                malformed("$expectedMethod did not confirm the deleted objects")
            }
        }

        fun requireAccount(payload: JsonObject, expectedAccountId: String) {
            if (payload.requiredString("accountId") != expectedAccountId) {
                malformed("JMAP response belonged to another Account")
            }
        }

        fun JsonObject.enabledProtocols(): Set<StalwartProductProtocol> {
            val permissions = requiredObject("permissions")
            if (permissions.requiredString("@type") == "Inherit") {
                return setOf(
                    StalwartProductProtocol.JMAP,
                    StalwartProductProtocol.SMTP,
                )
            }
            val enabled = permissions.requiredObject("enabledPermissions")
                .filterValues { value -> value.jsonPrimitive.booleanOrNull == true }
                .keys
            return buildSet {
                if (enabled.any { it.startsWith("jmap") }) add(StalwartProductProtocol.JMAP)
                if ("emailSend" in enabled) {
                    add(StalwartProductProtocol.SMTP)
                }
            }
        }

        fun JsonObject.addresses(property: String): List<String> =
            (this[property] as? JsonArray).orEmpty().mapNotNull { value ->
                val address = value as? JsonObject ?: return@mapNotNull null
                val email = address.optionalString("email") ?: return@mapNotNull null
                address.optionalString("name")
                    ?.takeIf(String::isNotBlank)
                    ?.let { name -> "$name <$email>" }
                    ?: email
            }

        fun JsonObject.firstBodyValue(
            property: String,
            bodyValues: JsonObject,
        ): String? {
            val partId = (this[property] as? JsonArray)
                ?.firstOrNull()
                ?.let { it as? JsonObject }
                ?.optionalString("partId")
                ?: return null
            return (bodyValues[partId] as? JsonObject)?.optionalString("value")
        }

        fun JsonObject.trueMapKeys(property: String): Set<String> =
            (this[property] as? JsonObject)
                .orEmpty()
                .filterValues { value -> value.jsonPrimitive.booleanOrNull == true }
                .keys

        fun JsonObject.optionalStringArray(property: String): List<String> =
            when (val value = this[property]) {
                null, JsonNull -> emptyList()
                is JsonArray -> value.map { it.requiredStringValue(property) }
                else -> malformed("$property was not an array")
            }

        fun JsonObject.requiredObject(property: String): JsonObject =
            this[property] as? JsonObject ?: malformed("$property was not an object")

        fun JsonObject.optionalObject(property: String): JsonObject? =
            when (val value = this[property]) {
                null, JsonNull -> null
                is JsonObject -> value
                else -> malformed("$property was not an object")
            }

        fun JsonObject.requiredArray(property: String): JsonArray =
            this[property] as? JsonArray ?: malformed("$property was not an array")

        fun JsonObject.requiredString(property: String): String =
            this[property].requiredStringValue(property)

        fun JsonObject.optionalString(property: String): String? =
            when (val value = this[property]) {
                null, JsonNull -> null
                else -> value.requiredStringValue(property)
            }

        fun JsonObject.requiredInt(property: String): Int =
            optionalInt(property) ?: malformed("$property was not an integer")

        fun JsonObject.optionalInt(property: String): Int? =
            when (val value = this[property]) {
                null, JsonNull -> null
                is JsonPrimitive -> value.takeUnless(JsonPrimitive::isString)?.intOrNull
                    ?: malformed("$property was not an integer")
                else -> malformed("$property was not an integer")
            }

        fun JsonElement?.requiredStringValue(label: String): String {
            val primitive = this as? JsonPrimitive
            if (primitive == null || !primitive.isString) {
                malformed("$label was not a string")
            }
            return primitive.content
        }

        fun JsonElement.requiredObjectValue(label: String): JsonObject =
            this as? JsonObject ?: malformed("$label was not an object")

        fun parseAddress(value: String): ParsedAddress {
            val match = ADDRESS.matchEntire(value)
                ?: throw IllegalArgumentException("Account address is invalid")
            return ParsedAddress(
                localPart = match.groupValues[1],
                domain = match.groupValues[2].lowercase(),
            )
        }

        fun requirePassword(value: String, label: String) {
            require(value.isNotEmpty() && value.length <= 4_096) {
                "$label is absent or too large"
            }
            require(value.none { it == '\u0000' || it == '\r' || it == '\n' }) {
                "$label contains an unsupported delimiter"
            }
        }

        fun malformed(message: String): Nothing = throw StalwartProductException(message)

        val ADDRESS = Regex("([a-z0-9][a-z0-9._+%-]{0,63})@(local\\.test)")
    }

    private data class ParsedAddress(
        val localPart: String,
        val domain: String,
    )
}
