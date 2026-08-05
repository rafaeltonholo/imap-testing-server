package mail.sandbox.dashboard.server.gate.stalwart

import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import mail.sandbox.dashboard.server.provider.stalwart.StalwartRuntimeSecretLoader
import mail.sandbox.dashboard.server.provider.stalwart.StalwartRuntimeSecretPaths
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStoreLoadResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStoreQuarantineResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStorePaths
import mail.sandbox.dashboard.server.provider.stalwart.credential.CredentialStoreWriteResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.FileStalwartCredentialStore
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartBorrowedSecret
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialLeaseRegistry
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialManagementRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialOwnerRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialProbeResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialRecord
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialSnapshot
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartCredentialStore
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartGlobalReservedInventory
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessService
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccessState
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailAccount
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailCredentialLease
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailCredentialProbeRemote
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailLeaseAcquireResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartMailLeaseUnavailableReason
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartNormalPassword
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteCreateResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteMutationResult
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartRemoteRead
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedCredential
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartReservedInventory
import kotlin.system.exitProcess
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

internal data class StalwartRoutingProofPaths(
    val input: Path,
    val senderPassword: Path,
    val recipientPassword: Path,
) {
    companion object {
        fun fixed(dashboardProjectRoot: Path): StalwartRoutingProofPaths =
            StalwartRoutingProofPaths(
                input = dashboardProjectRoot.resolve(
                    ".runtime/stalwart/bootstrap-routing-input.json",
                ),
                senderPassword = dashboardProjectRoot.resolve(
                    ".runtime/secrets/stalwart-routing-sender-password",
                ),
                recipientPassword = dashboardProjectRoot.resolve(
                    ".runtime/secrets/stalwart-routing-recipient-password",
                ),
            )
    }
}

internal data class StalwartRoutingProofArguments(
    val dashboardProjectRoot: Path,
    val invocationId: String,
    val paths: StalwartRoutingProofPaths,
) {
    val endpointProfile: StalwartEndpointProfile
        get() = StalwartEndpointProfile.MIGRATION_BOOTSTRAP

    companion object {
        fun parse(args: Array<String>): StalwartRoutingProofArguments {
            require(
                args.size == 4 &&
                    args[0] == "--dashboard-project-root" &&
                    args[2] == "--invocation-id",
            ) {
                "Routing verifier arguments are invalid"
            }
            val configuredRoot = runCatching { Path.of(args[1]) }
                .getOrElse {
                    throw IllegalArgumentException(
                        "Dashboard project root is invalid",
                    )
                }
            require(
                configuredRoot.isAbsolute &&
                    configuredRoot.normalize() == configuredRoot,
            ) {
                "Dashboard project root must be a normalized absolute path"
            }
            val canonicalRoot = runCatching {
                configuredRoot.toRealPath(LinkOption.NOFOLLOW_LINKS)
            }.getOrElse {
                throw IllegalArgumentException(
                    "Dashboard project root is unavailable",
                )
            }
            require(
                !Files.isSymbolicLink(configuredRoot) &&
                    canonicalRoot.fileName?.toString() == "debug-dashboard" &&
                    Files.isRegularFile(
                        canonicalRoot.resolve("project.yaml"),
                        LinkOption.NOFOLLOW_LINKS,
                    ),
            ) {
                "Dashboard project root is not the fixed Kotlin project"
            }
            val invocationId = args[3]
            require(INVOCATION_ID.matches(invocationId)) {
                "Routing invocation ID is invalid"
            }
            return StalwartRoutingProofArguments(
                dashboardProjectRoot = canonicalRoot,
                invocationId = invocationId,
                paths = StalwartRoutingProofPaths.fixed(canonicalRoot),
            )
        }

        private val INVOCATION_ID = Regex("[0-9a-f]{32}")
    }
}

internal data class StalwartRoutingInputActor(
    val accountId: String,
    val address: String,
)

internal data class StalwartRoutingProofInput(
    val serverVersion: String,
    val invocationId: String,
    val managementAccountId: String,
    val managementCredentialId: String,
    val bootstrapProof: JsonObject,
    val preservedObjectsSha256: String,
    val sender: StalwartRoutingInputActor,
    val recipient: StalwartRoutingInputActor,
) {
    override fun toString(): String =
        "StalwartRoutingProofInput(values=validated, secrets=absent)"
}

internal object StalwartRoutingProofInputFiles {
    fun read(arguments: StalwartRoutingProofArguments): StalwartRoutingProofInput {
        val content = readOwnerOnlyRegular(
            root = arguments.dashboardProjectRoot,
            path = arguments.paths.input,
            maximumBytes = MAXIMUM_INPUT_BYTES,
            label = "routing verifier input",
        )
        val text = content.toString(StandardCharsets.UTF_8)
        val parsed = try {
            Json.parseToJsonElement(text.trimEnd('\n')).jsonObject
        } catch (_: Exception) {
            throw IllegalArgumentException(
                "Routing verifier input is malformed",
            )
        } finally {
            content.fill(0)
        }
        require(text == StalwartRoutingCanonicalJson.encode(parsed) + "\n") {
            "Routing verifier input is not canonical JSON"
        }
        return parse(arguments, parsed)
    }

    private fun parse(
        arguments: StalwartRoutingProofArguments,
        value: JsonObject,
    ): StalwartRoutingProofInput {
        require(
            value.keys == setOf(
                "actors",
                "bootstrap_proof",
                "invocation_id",
                "management_account_id",
                "management_credential_id",
                "preserved_objects_sha256",
                "schema",
                "server_version",
            ),
        ) {
            "Routing verifier input fields are invalid"
        }
        require(
            value.requiredString("schema") == INPUT_SCHEMA &&
                value.requiredString("server_version") == SERVER_VERSION &&
                value.requiredString("invocation_id") == arguments.invocationId,
        ) {
            "Routing verifier input metadata is invalid"
        }
        val actors = value.requiredObject("actors")
        require(actors.keys == setOf("recipient", "sender")) {
            "Routing verifier actors are invalid"
        }
        val sender = inputActor(
            value = actors.requiredObject("sender"),
            role = "sender",
            invocationId = arguments.invocationId,
        )
        val recipient = inputActor(
            value = actors.requiredObject("recipient"),
            role = "recipient",
            invocationId = arguments.invocationId,
        )
        val managementAccountId = value.requiredSafeId(
            "management_account_id",
        )
        val managementCredentialId = value.requiredSafeId(
            "management_credential_id",
        )
        require(
            setOf(
                managementAccountId,
                sender.accountId,
                recipient.accountId,
            ).size == 3,
        ) {
            "Routing verifier Account IDs are not distinct"
        }
        return StalwartRoutingProofInput(
            serverVersion = SERVER_VERSION,
            invocationId = arguments.invocationId,
            managementAccountId = managementAccountId,
            managementCredentialId = managementCredentialId,
            bootstrapProof = validateBootstrapProof(
                value.requiredObject("bootstrap_proof"),
            ),
            preservedObjectsSha256 = value.requiredSha256(
                "preserved_objects_sha256",
            ),
            sender = sender,
            recipient = recipient,
        )
    }

    private fun inputActor(
        value: JsonObject,
        role: String,
        invocationId: String,
    ): StalwartRoutingInputActor {
        require(value.keys == setOf("account_id", "address")) {
            "Routing verifier $role actor is invalid"
        }
        val expectedAddress =
            "dashboard-routing-$role-$invocationId@local.test"
        require(value.requiredString("address") == expectedAddress) {
            "Routing verifier $role address is invalid"
        }
        return StalwartRoutingInputActor(
            accountId = value.requiredSafeId("account_id"),
            address = expectedAddress,
        )
    }

    private const val MAXIMUM_INPUT_BYTES = 64 * 1024
}

internal object StalwartRoutingCanonicalJson {
    fun encode(value: JsonElement): String = when (value) {
        is JsonObject -> value.keys.sorted().joinToString(
            prefix = "{",
            postfix = "}",
            separator = ",",
        ) { key ->
            JsonPrimitive(key).toString() + ":" +
                encode(requireNotNull(value[key]))
        }

        is JsonArray -> value.joinToString(
            prefix = "[",
            postfix = "]",
            separator = ",",
            transform = ::encode,
        )

        is JsonPrimitive -> value.toString()
        JsonNull -> "null"
    }
}

internal object StalwartRoutingEvidenceSecretAudit {
    fun requireSecretFree(
        value: JsonElement,
        forbiddenValues: List<CharArray>,
    ) {
        forbiddenValues.forEach {
            require(it.isNotEmpty()) { "Forbidden routing secret is absent" }
        }
        visit(value, forbiddenValues)
    }

    private fun visit(
        value: JsonElement,
        forbiddenValues: List<CharArray>,
    ) {
        when (value) {
            is JsonObject -> value.forEach { (name, child) ->
                require(name !in FORBIDDEN_SECRET_FIELDS) {
                    "Routing evidence contains a forbidden secret field"
                }
                visit(child, forbiddenValues)
            }

            is JsonArray -> value.forEach {
                visit(it, forbiddenValues)
            }

            is JsonPrimitive -> if (value.isString) {
                require(
                    forbiddenValues.none {
                        value.content.matchesSecret(it)
                    },
                ) {
                    "Routing evidence contains a forbidden secret value"
                }
            }

            JsonNull -> Unit
        }
    }

    private fun String.matchesSecret(secret: CharArray): Boolean =
        length == secret.size &&
            indices.all { index -> this[index] == secret[index] }

    private val FORBIDDEN_SECRET_FIELDS = setOf(
        "api_key",
        "api_key_path",
        "app_password",
        "app_password_secret",
        "authorization",
        "bearer_token",
        "management_key",
        "management_key_path",
        "normal_password",
        "password",
        "password_path",
        "recipient_password",
        "recipient_password_path",
        "secret",
        "secret_path",
        "sender_password",
        "sender_password_path",
        "token",
    )
}

internal data class StalwartRoutingActorEvidence(
    val accountId: String,
    val address: String,
    val appPasswordCredentialId: String,
)

internal data class StalwartRoutingVerifierEvidence(
    val serverVersion: String,
    val managementAccountId: String,
    val managementCredentialId: String,
    val bootstrapProof: JsonObject,
    val preservedObjectsSha256: String,
    val sender: StalwartRoutingActorEvidence,
    val recipient: StalwartRoutingActorEvidence,
    val messageId: String,
    val probes: Map<String, JsonObject>,
    val recipientAccessRemoved: JsonObject,
) {
    override fun toString(): String =
        "StalwartRoutingVerifierEvidence(values=validated, secrets=absent)"
}

internal data class StalwartRoutingProofRequest(
    val dashboardProjectRoot: Path,
    val invocationId: String,
    val endpointProfile: StalwartEndpointProfile,
    val paths: StalwartRoutingProofPaths,
)

internal interface StalwartRoutingProofWorkflow : AutoCloseable {
    suspend fun prove(
        request: StalwartRoutingProofRequest,
    ): StalwartRoutingVerifierEvidence
}

internal fun interface StalwartRoutingProofWorkflowFactory {
    fun create(
        request: StalwartRoutingProofRequest,
    ): StalwartRoutingProofWorkflow
}

internal enum class StalwartRoutingActorRole(
    val value: String,
) {
    SENDER("sender"),
    RECIPIENT("recipient"),
}

internal data class StalwartRoutingProbeSpec(
    val name: String,
    val recipient: String,
    val enhancedStatus: String,
    val registeredLocal: Boolean,
)

internal interface StalwartRoutingMailRemote : AutoCloseable {
    suspend fun enroll(
        role: StalwartRoutingActorRole,
        actor: StalwartRoutingInputActor,
        normalPassword: CharArray,
    ): String

    suspend fun submit(
        probe: StalwartRoutingProbeSpec,
        messageId: String,
    ): JsonObject

    suspend fun awaitRegisteredArrival(
        recipientAccountId: String,
        messageId: String,
    ): List<String>

    suspend fun cleanupMailArtifacts()

    suspend fun revoke(
        role: StalwartRoutingActorRole,
        credentialId: String,
    )

    suspend fun appPasswordInventory(
        role: StalwartRoutingActorRole,
    ): Set<String>

    suspend fun revokedAuthenticationStatus(
        role: StalwartRoutingActorRole,
    ): Int

    suspend fun readinessPreflight(
        role: StalwartRoutingActorRole,
    ): StalwartRoutingReadinessEvidence

    suspend fun cleanup()
}

internal fun interface StalwartRoutingMailRemoteFactory {
    fun create(
        request: StalwartRoutingProofRequest,
        input: StalwartRoutingProofInput,
    ): StalwartRoutingMailRemote
}

internal fun interface StalwartRoutingReadinessPreflight {
    suspend fun requireUnavailable(
        account: StalwartMailAccount,
    ): StalwartMailAccessState
}

internal data class StalwartRoutingReadinessEvidence(
    val projectedState: StalwartMailAccessState,
    val submissionCalls: Int,
    val uploadCalls: Int,
)

internal object ProductionStalwartRoutingReadinessPreflight :
    StalwartRoutingReadinessPreflight {
    override suspend fun requireUnavailable(
        account: StalwartMailAccount,
    ): StalwartMailAccessState {
        val service = StalwartMailAccessService(
            store = EmptyCredentialStore,
            management = FailFastManagementRemote,
            owner = FailFastOwnerRemote,
            probe = FailFastProbeRemote,
            leases = StalwartCredentialLeaseRegistry(),
            protectedAccountIds = emptySet(),
        )
        val result = service.acquireMailLease(account)
        require(
            result ==
                StalwartMailLeaseAcquireResult.Unavailable(
                    StalwartMailLeaseUnavailableReason.NotReady,
                ),
        ) {
            "Unenrolled routing Account unexpectedly acquired mail access"
        }
        return StalwartMailAccessState.EnrollmentRequired
    }

    private object EmptyCredentialStore : StalwartCredentialStore {
        override fun load(): CredentialStoreLoadResult =
            CredentialStoreLoadResult.Available(
                StalwartCredentialSnapshot(
                    storeId = STORE_ID,
                    revision = 0,
                    records = emptyMap(),
                ),
            )

        override fun replace(
            expectedRevision: Long,
            records: Map<String, StalwartCredentialRecord>,
        ): CredentialStoreWriteResult =
            error("Routing readiness must not mutate the credential store")

        override fun quarantineUnavailable():
            CredentialStoreQuarantineResult =
            error("Routing readiness must not quarantine the credential store")

        override fun close() = Unit
    }

    private object FailFastManagementRemote :
        StalwartCredentialManagementRemote {
        override suspend fun inventory(
            accountId: String,
        ): StalwartRemoteRead<StalwartReservedInventory> =
            error("Routing readiness must not inventory remote credentials")

        override suspend fun globalInventory():
            StalwartRemoteRead<StalwartGlobalReservedInventory> =
            error("Routing readiness must not inventory global credentials")

        override suspend fun revokeReserved(
            accountId: String,
            expected: Set<StalwartReservedCredential>,
            targets: Set<StalwartReservedCredential>,
        ): StalwartRemoteMutationResult =
            error("Routing readiness must not revoke remote credentials")
    }

    private object FailFastOwnerRemote : StalwartCredentialOwnerRemote {
        override suspend fun createOwned(
            account: StalwartMailAccount,
            description: String,
            normalPassword: StalwartNormalPassword,
        ): StalwartRemoteCreateResult =
            error("Routing readiness must not create remote credentials")
    }

    private object FailFastProbeRemote : StalwartMailCredentialProbeRemote {
        override suspend fun probe(
            accountId: String,
            address: String,
            secret: StalwartBorrowedSecret,
        ): StalwartCredentialProbeResult =
            error("Routing readiness must not authenticate remote credentials")
    }

    private val STORE_ID =
        UUID.fromString("00000000-0000-0000-0000-000000000001")
}

internal class StalwartRoutingPassword private constructor(
    value: CharArray,
) : AutoCloseable {
    private val value = value.copyOf()
    private var closed = false

    @Synchronized
    fun copyValue(): CharArray {
        check(!closed) { "Routing password is closed" }
        return value.copyOf()
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        value.fill('\u0000')
    }

    override fun toString(): String =
        "StalwartRoutingPassword(value=redacted)"

    companion object {
        fun read(
            root: Path,
            path: Path,
        ): StalwartRoutingPassword {
            val bytes = readOwnerOnlyRegular(
                root = root,
                path = path,
                maximumBytes = MAXIMUM_PASSWORD_BYTES,
                label = "routing actor password",
            )
            var chars = CharArray(0)
            return try {
                require(
                    bytes.size in 1..MAXIMUM_PASSWORD_CHARS &&
                        bytes.all {
                            it.toInt() and 0xff in
                                VISIBLE_ASCII_FIRST..VISIBLE_ASCII_LAST
                        },
                ) {
                    "Routing actor password is malformed"
                }
                chars = CharArray(bytes.size) { index ->
                    (bytes[index].toInt() and 0xff).toChar()
                }
                StalwartRoutingPassword(chars)
            } finally {
                bytes.fill(0)
                chars.fill('\u0000')
            }
        }

        private const val MAXIMUM_PASSWORD_BYTES = 4 * 1024
        private const val MAXIMUM_PASSWORD_CHARS = 1024
        private const val VISIBLE_ASCII_FIRST = 0x21
        private const val VISIBLE_ASCII_LAST = 0x7e
    }
}

internal class StalwartRoutingLiveWorkflow(
    private val remoteFactory: StalwartRoutingMailRemoteFactory =
        StalwartRoutingMailRemoteFactory { request, input ->
            KtorStalwartRoutingMailRemote(request, input)
        },
) : StalwartRoutingProofWorkflow {
    override suspend fun prove(
        request: StalwartRoutingProofRequest,
    ): StalwartRoutingVerifierEvidence {
        require(
            request.endpointProfile ==
                StalwartEndpointProfile.MIGRATION_BOOTSTRAP,
        ) {
            "Routing verifier endpoint profile is invalid"
        }
        val arguments = StalwartRoutingProofArguments(
            dashboardProjectRoot = request.dashboardProjectRoot,
            invocationId = request.invocationId,
            paths = request.paths,
        )
        require(
            request.paths ==
                StalwartRoutingProofPaths.fixed(request.dashboardProjectRoot),
        ) {
            "Routing verifier paths are not fixed"
        }
        val input = StalwartRoutingProofInputFiles.read(arguments)
        require(input.invocationId == request.invocationId) {
            "Routing verifier input belongs to another invocation"
        }
        var remote: StalwartRoutingMailRemote? = null
        var primaryFailure: Throwable? = null
        try {
            remote = remoteFactory.create(request, input)
            val senderCredentialId = enroll(
                remote = remote,
                role = StalwartRoutingActorRole.SENDER,
                actor = input.sender,
                root = request.dashboardProjectRoot,
                path = request.paths.senderPassword,
            )
            val recipientCredentialId = enroll(
                remote = remote,
                role = StalwartRoutingActorRole.RECIPIENT,
                actor = input.recipient,
                root = request.dashboardProjectRoot,
                path = request.paths.recipientPassword,
            )
            val messageId =
                "<mail-sandbox-routing-${request.invocationId}@local.test>"
            val probes = linkedMapOf<String, JsonObject>()
            val registered = probeSpecs(
                request.invocationId,
                input.recipient.address,
            ).first()
            val registeredResult = remote.submit(registered, messageId)
            val matchingEmailIds = remote.awaitRegisteredArrival(
                recipientAccountId = input.recipient.accountId,
                messageId = messageId,
            )
            probes[registered.name] = JsonObject(
                registeredResult + (
                    "arrival" to buildJsonObject {
                        put("account_id", input.recipient.accountId)
                        put(
                            "matching_email_ids",
                            JsonArray(
                                matchingEmailIds.map(::JsonPrimitive),
                            ),
                        )
                        put("message_id", messageId)
                    }
                    ),
            )
            probeSpecs(
                request.invocationId,
                input.recipient.address,
            ).drop(1).forEach { probe ->
                probes[probe.name] = remote.submit(probe, messageId)
            }

            remote.cleanupMailArtifacts()
            remote.revoke(
                StalwartRoutingActorRole.RECIPIENT,
                recipientCredentialId,
            )
            require(
                remote.appPasswordInventory(
                    StalwartRoutingActorRole.RECIPIENT,
                ).isEmpty(),
            ) {
                "Recipient AppPassword inventory was not empty"
            }
            val authenticationStatus = remote.revokedAuthenticationStatus(
                StalwartRoutingActorRole.RECIPIENT,
            )
            val readinessPreflight = remote.readinessPreflight(
                StalwartRoutingActorRole.RECIPIENT,
            )
            remote.revoke(
                StalwartRoutingActorRole.SENDER,
                senderCredentialId,
            )
            require(
                remote.appPasswordInventory(
                    StalwartRoutingActorRole.SENDER,
                ).isEmpty(),
            ) {
                "Sender AppPassword inventory was not empty"
            }
            return StalwartRoutingVerifierEvidence(
                serverVersion = input.serverVersion,
                managementAccountId = input.managementAccountId,
                managementCredentialId = input.managementCredentialId,
                bootstrapProof = input.bootstrapProof,
                preservedObjectsSha256 = input.preservedObjectsSha256,
                sender = StalwartRoutingActorEvidence(
                    accountId = input.sender.accountId,
                    address = input.sender.address,
                    appPasswordCredentialId = senderCredentialId,
                ),
                recipient = StalwartRoutingActorEvidence(
                    accountId = input.recipient.accountId,
                    address = input.recipient.address,
                    appPasswordCredentialId = recipientCredentialId,
                ),
                messageId = messageId,
                probes = probes,
                recipientAccessRemoved = buildJsonObject {
                    put("authentication_status", authenticationStatus)
                    put("credential_id", recipientCredentialId)
                    put(
                        "projected_state",
                        when (readinessPreflight.projectedState) {
                            StalwartMailAccessState.EnrollmentRequired ->
                                "enrollmentRequired"

                            else -> throw IllegalArgumentException(
                                "Routing readiness projected another state",
                            )
                        },
                    )
                    put(
                        "readiness_preflight",
                        buildJsonObject {
                            put(
                                "submission_calls",
                                readinessPreflight.submissionCalls,
                            )
                            put(
                                "upload_calls",
                                readinessPreflight.uploadCalls,
                            )
                        },
                    )
                },
            )
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            val cleanupFailure = withContext(NonCancellable) {
                var failure: Throwable? = null
                try {
                    remote?.cleanup()
                } catch (cleanup: Throwable) {
                    failure = cleanup
                }
                try {
                    remote?.close()
                } catch (close: Throwable) {
                    failure?.addSuppressed(close) ?: run { failure = close }
                }
                failure
            }
            if (cleanupFailure != null) {
                if (primaryFailure != null) {
                    primaryFailure.addSuppressed(cleanupFailure)
                } else {
                    throw cleanupFailure
                }
            }
        }
    }

    private suspend fun enroll(
        remote: StalwartRoutingMailRemote,
        role: StalwartRoutingActorRole,
        actor: StalwartRoutingInputActor,
        root: Path,
        path: Path,
    ): String {
        StalwartRoutingPassword.read(root, path).use { password ->
            val clear = password.copyValue()
            return try {
                remote.enroll(role, actor, clear)
            } finally {
                clear.fill('\u0000')
            }
        }
    }

    override fun close() = Unit

    private fun probeSpecs(
        invocationId: String,
        registeredAddress: String,
    ): List<StalwartRoutingProbeSpec> = listOf(
        StalwartRoutingProbeSpec(
            name = "registered_local",
            recipient = registeredAddress,
            enhancedStatus = "2.1.5",
            registeredLocal = true,
        ),
        StalwartRoutingProbeSpec(
            name = "protected_exact",
            recipient = MANAGEMENT_ADDRESS,
            enhancedStatus = "5.7.1",
            registeredLocal = false,
        ),
        StalwartRoutingProbeSpec(
            name = "protected_subaddress",
            recipient =
                "dashboard-management+routing-$invocationId@local.test",
            enhancedStatus = "5.7.1",
            registeredLocal = false,
        ),
        StalwartRoutingProbeSpec(
            name = "unregistered_local",
            recipient =
                "dashboard-routing-missing-$invocationId@local.test",
            enhancedStatus = "5.1.2",
            registeredLocal = false,
        ),
        StalwartRoutingProbeSpec(
            name = "external",
            recipient =
                "dashboard-routing-$invocationId@example.invalid",
            enhancedStatus = "5.1.2",
            registeredLocal = false,
        ),
    )
}

internal object StalwartRoutingSubmissionNormalizer {
    fun normalize(
        probe: StalwartRoutingProbeSpec,
        submissionId: String,
        undoStatus: String,
        deliveryStatus: JsonObject,
    ): JsonObject {
        safeId(submissionId, "routing submission ID")
        require(deliveryStatus.keys == setOf(probe.recipient)) {
            "Routing delivery status belongs to another recipient"
        }
        val recipientStatus = deliveryStatus.requiredObject(probe.recipient)
        require(
            recipientStatus.keys ==
                setOf("delivered", "displayed", "smtpReply"),
        ) {
            "Routing delivery status is malformed"
        }
        val delivered = recipientStatus.requiredString("delivered")
        require(recipientStatus.requiredString("displayed") == "unknown") {
            "Routing displayed status is not source-defined"
        }
        val reply = recipientStatus.requiredString("smtpReply")
        val match = SMTP_REPLY.matchEntire(reply)
            ?: throw IllegalArgumentException(
                "Routing SMTP reply is malformed",
            )
        val smtpCode = match.groupValues[1].toInt()
        val enhancedStatus = match.groupValues[2]
        val expectedDelivered = if (probe.registeredLocal) {
            "unknown"
        } else {
            "no"
        }
        val expectedUndo = if (probe.registeredLocal) {
            "final"
        } else {
            "pending"
        }
        val expectedCode = if (probe.registeredLocal) 250 else 550
        require(
            delivered == expectedDelivered &&
                undoStatus == expectedUndo &&
                smtpCode == expectedCode &&
                enhancedStatus == probe.enhancedStatus,
        ) {
            "Routing submission outcome differs from the required policy"
        }
        return buildJsonObject {
            put("delivery_status", expectedDelivered)
            put("enhanced_status", enhancedStatus)
            put("queue_accepted", probe.registeredLocal)
            put("recipient", probe.recipient)
            put("smtp_code", smtpCode)
            put("submission_created", true)
            put("submission_id", submissionId)
            put("undo_status", expectedUndo)
        }
    }

    private val SMTP_REPLY =
        Regex("([0-9]{3}) ([245]\\.[0-9]\\.[0-9])(?: .*)?")
}

internal class StalwartRoutingNormalCredentialTransport(
    private val delegate: GateHttpTransport,
) : GateHttpTransport {
    override suspend fun execute(
        request: GateHttpRequest,
    ): GateHttpResponse {
        when (request.method) {
            "GET" -> require(
                request.body == null &&
                    request.url.path == "/.well-known/jmap" &&
                    request.url.rawQuery == null &&
                    request.url.rawFragment == null,
            ) {
                "Normal passwords may only discover the JMAP Session"
            }

            "POST" -> {
                val calls = requireNotNull(request.body)
                    .requiredArray("methodCalls")
                require(calls.size == 1) {
                    "Normal-password request contained multiple methods"
                }
                val call = calls.single() as? JsonArray
                require(call != null && call.size == 3) {
                    "Normal-password request method tuple is malformed"
                }
                val methodName = call[0].requiredStringValue(
                    "normal-password JMAP method",
                )
                require(methodName in APP_PASSWORD_METHODS) {
                    "Normal passwords may only manage AppPasswords"
                }
            }
        }
        return delegate.execute(request)
    }

    private companion object {
        val APP_PASSWORD_METHODS = setOf(
            "x:AppPassword/get",
            "x:AppPassword/query",
            "x:AppPassword/set",
        )
    }
}

internal data class StalwartRoutingDispatchSnapshot(
    val uploadCalls: Int,
    val submissionCalls: Int,
)

internal class StalwartRoutingMailDispatchTransport(
    private val delegate: GateHttpTransport,
) : GateHttpTransport {
    private var uploadCalls = 0
    private var submissionCalls = 0

    override suspend fun execute(
        request: GateHttpRequest,
    ): GateHttpResponse {
        if (request.method == "POST") {
            val calls = requireNotNull(request.body)
                .requiredArray("methodCalls")
            require(calls.size == 1) {
                "Routing mail request contained multiple methods"
            }
            val call = calls.single() as? JsonArray
            require(call != null && call.size == 3) {
                "Routing mail request method tuple is malformed"
            }
            when (
                call[0].requiredStringValue("routing mail JMAP method")
            ) {
                "Blob/upload" -> incrementUpload()
                "EmailSubmission/set" -> incrementSubmission()
            }
        }
        return delegate.execute(request)
    }

    @Synchronized
    fun snapshot(): StalwartRoutingDispatchSnapshot =
        StalwartRoutingDispatchSnapshot(
            uploadCalls = uploadCalls,
            submissionCalls = submissionCalls,
        )

    @Synchronized
    private fun incrementUpload() {
        uploadCalls += 1
    }

    @Synchronized
    private fun incrementSubmission() {
        submissionCalls += 1
    }
}

internal class KtorStalwartRoutingMailRemote(
    private val request: StalwartRoutingProofRequest,
    private val input: StalwartRoutingProofInput,
    private val transport: GateHttpTransport =
        KtorGateHttpTransport(followRedirects = false),
    private val readinessPreflight: StalwartRoutingReadinessPreflight =
        ProductionStalwartRoutingReadinessPreflight,
) : StalwartRoutingMailRemote {
    private val lifecycleProfile = request.endpointProfile.also { profile ->
        require(profile == StalwartEndpointProfile.MIGRATION_BOOTSTRAP) {
            "Routing mail lifecycle used the wrong endpoint profile"
        }
    }
    private val mailTransport =
        StalwartRoutingMailDispatchTransport(transport)
    private val store = FileStalwartCredentialStore(
        CredentialStorePaths.production(request.dashboardProjectRoot),
    )
    private val leases = StalwartCredentialLeaseRegistry()
    private val managementClient = createManagementClient()
    private val management = GateStalwartCredentialManagementRemote(
        registry = managementClient,
        managementAccountId = input.managementAccountId,
        protectedAccountIds = setOf(input.managementAccountId),
        endpointProfile = lifecycleProfile,
    )
    private val owner = GateStalwartCredentialOwnerRemote(
        endpointProfile = lifecycleProfile,
        transport = StalwartRoutingNormalCredentialTransport(transport),
    )
    private val probe = GateStalwartMailCredentialProbeRemote(
        endpointProfile = lifecycleProfile,
        transport = transport,
    )
    private val service = StalwartMailAccessService(
        store = store,
        management = management,
        owner = owner,
        probe = probe,
        leases = leases,
        protectedAccountIds = setOf(input.managementAccountId),
    )
    private val actors =
        linkedMapOf<StalwartRoutingActorRole, RoutingActorConnection>()
    private val senderEmailIds = linkedSetOf<String>()
    private val senderSubmissionIds = linkedSetOf<String>()
    private val recipientEmailIds = linkedSetOf<String>()
    private val attemptedSubjects = linkedSetOf<String>()
    private var senderMailboxId: String? = null
    private var senderIdentityId: String? = null
    private var registeredSubject: String? = null
    private var mailArtifactsClean = false
    private var closed = false

    override suspend fun enroll(
        role: StalwartRoutingActorRole,
        actor: StalwartRoutingInputActor,
        normalPassword: CharArray,
    ): String {
        requireOpen()
        val password = StalwartNormalPassword.takeOwnership(normalPassword)
        val account = actor.mailAccount()
        var lease: StalwartMailCredentialLease? = null
        var appClient: GateJmapClient? = null
        var revocationCredential: GateCredential? = null
        try {
            require(
                role !in actors &&
                    actor == when (role) {
                        StalwartRoutingActorRole.SENDER -> input.sender
                        StalwartRoutingActorRole.RECIPIENT -> input.recipient
                    },
            ) {
                "Routing actor enrollment is invalid"
            }
            requireCompletedState(
                result = service.enroll(account, password),
                expected = StalwartMailAccessState.Ready,
                operation = "Routing enrollment",
            )
            val inventory = requireInventory(account)
            require(
                inventory.reserved.size == 1 &&
                    inventory.appPasswordCount == 1,
            ) {
                "Routing enrollment credential inventory was not exact"
            }
            val credentialId = inventory.reserved.single().credentialId
            lease = when (val acquired = service.acquireMailLease(account)) {
                is StalwartMailLeaseAcquireResult.Acquired -> acquired.lease
                is StalwartMailLeaseAcquireResult.Unavailable ->
                    throw IllegalStateException(
                        "Routing enrollment did not acquire mail access",
                    )
            }
            require(
                lease.accountId == account.accountId &&
                    lease.generation == 1L,
            ) {
                "Routing enrollment acquired another credential generation"
            }
            lease.withSecret { secret ->
                val chars = secret.toRoutingAsciiChars()
                try {
                    appClient = GateJmapClient(
                        profile = lifecycleProfile,
                        credential = GateCredential.basic(
                            username = actor.address,
                            secret = chars,
                        ),
                        transport = mailTransport,
                    )
                    revocationCredential = GateCredential.basic(
                        username = actor.address,
                        secret = chars,
                    )
                } finally {
                    chars.fill('\u0000')
                }
            }
            requireActorSession(
                requireNotNull(appClient).discoverSession(),
                actor,
            )
            actors[role] = RoutingActorConnection(
                role = role,
                actor = actor,
                lease = lease,
                appClient = requireNotNull(appClient),
                revocationCredential =
                    requireNotNull(revocationCredential),
                credentialId = credentialId,
            )
            lease = null
            appClient = null
            revocationCredential = null
            return credentialId
        } catch (failure: Throwable) {
            appClient?.close()
            appClient = null
            revocationCredential?.close()
            revocationCredential = null
            lease?.close()
            lease = null
            val cleanupFailure = withContext(NonCancellable) {
                runCatching { removeAndVerify(account) }.exceptionOrNull()
            }
            cleanupFailure?.let(failure::addSuppressed)
            throw failure
        } finally {
            password.close()
        }
    }

    override suspend fun submit(
        probe: StalwartRoutingProbeSpec,
        messageId: String,
    ): JsonObject {
        requireOpen()
        val sender = actor(StalwartRoutingActorRole.SENDER)
        val mailboxId = senderMailboxId ?: findSenderMailbox(sender)
            .also { senderMailboxId = it }
        val identityId = senderIdentityId ?: findSenderIdentity(sender)
            .also { senderIdentityId = it }
        val subject =
            "mail-sandbox-routing-${request.invocationId}-${probe.name}"
        attemptedSubjects += subject
        if (probe.registeredLocal) {
            registeredSubject = subject
        }
        val emailId = importMessage(
            sender = sender,
            mailboxId = mailboxId,
            recipient = probe.recipient,
            subject = subject,
            messageId = messageId,
        )
        senderEmailIds += emailId
        val submissionId = createSubmission(
            sender = sender,
            emailId = emailId,
            identityId = identityId,
            recipient = probe.recipient,
        )
        senderSubmissionIds += submissionId
        var lastFailure: Throwable? = null
        repeat(SUBMISSION_STATUS_ATTEMPTS) { attempt ->
            try {
                return submissionOutcome(
                    sender = sender,
                    probe = probe,
                    submissionId = submissionId,
                )
            } catch (failure: IllegalArgumentException) {
                lastFailure = failure
            }
            if (attempt + 1 < SUBMISSION_STATUS_ATTEMPTS) {
                delay(SUBMISSION_STATUS_DELAY_MILLIS)
            }
        }
        throw IllegalStateException(
            "Routing submission did not reach its required normalized state",
            lastFailure,
        )
    }

    override suspend fun awaitRegisteredArrival(
        recipientAccountId: String,
        messageId: String,
    ): List<String> {
        requireOpen()
        val recipient = actor(StalwartRoutingActorRole.RECIPIENT)
        require(recipient.actor.accountId == recipientAccountId) {
            "Routing arrival Account is invalid"
        }
        val subject = requireNotNull(registeredSubject) {
            "Registered routing probe was not submitted"
        }
        repeat(ARRIVAL_ATTEMPTS) { attempt ->
            val ids = exactSubjectEmailIds(
                connection = recipient,
                subject = subject,
            )
            if (ids.isNotEmpty()) {
                require(ids.size == 1) {
                    "Registered routing delivery was duplicated"
                }
                val emailId = ids.single()
                requireEmailMessageId(
                    connection = recipient,
                    emailId = emailId,
                    subject = subject,
                    expectedMessageId = messageId,
                )
                recipientEmailIds += emailId
                return listOf(emailId)
            }
            if (attempt + 1 < ARRIVAL_ATTEMPTS) {
                delay(ARRIVAL_DELAY_MILLIS)
            }
        }
        throw IllegalStateException(
            "Registered routing message did not arrive",
        )
    }

    override suspend fun cleanupMailArtifacts() {
        requireOpen()
        if (mailArtifactsClean) return
        val sender = actors[StalwartRoutingActorRole.SENDER]
        val recipient = actors[StalwartRoutingActorRole.RECIPIENT]
        var failure: Throwable? = null

        suspend fun attempt(block: suspend () -> Unit) {
            try {
                block()
            } catch (cleanup: Throwable) {
                failure?.addSuppressed(cleanup) ?: run { failure = cleanup }
            }
        }

        if (sender != null) {
            attemptedSubjects.forEach { subject ->
                attempt {
                    senderEmailIds += exactSubjectEmailIds(
                        connection = sender,
                        subject = subject,
                    )
                }
            }
            attempt {
                senderSubmissionIds += relatedSubmissionIds(
                    sender,
                    senderEmailIds,
                )
            }
            // Stalwart's reviewed AppPassword baseline intentionally excludes
            // EmailSubmission destroy. The disposable sender Account remains
            // owned by the Python bootstrap actor, whose authoritative Account
            // destruction removes any retained submission objects.
            senderEmailIds.toList().forEach { emailId ->
                attempt {
                    destroyObject(
                        connection = sender,
                        methodName = "Email/set",
                        id = emailId,
                    )
                    senderEmailIds -= emailId
                }
            }
        }
        if (recipient != null) {
            registeredSubject?.let { subject ->
                attempt {
                    recipientEmailIds += exactSubjectEmailIds(
                        connection = recipient,
                        subject = subject,
                    )
                }
            }
            recipientEmailIds.toList().forEach { emailId ->
                attempt {
                    destroyObject(
                        connection = recipient,
                        methodName = "Email/set",
                        id = emailId,
                    )
                    recipientEmailIds -= emailId
                }
            }
        }
        if (failure == null) {
            require(
                senderEmailIds.isEmpty() &&
                    recipientEmailIds.isEmpty(),
            ) {
                "Routing mail cleanup did not drain owned artifacts"
            }
            mailArtifactsClean = true
        } else {
            throw failure
        }
    }

    override suspend fun revoke(
        role: StalwartRoutingActorRole,
        credentialId: String,
    ) {
        requireOpen()
        val connection = actor(role)
        require(connection.credentialId == credentialId) {
            "Routing revocation credential ID is invalid"
        }
        connection.releaseMailAccess()
        removeAndVerify(connection.actor.mailAccount())
        connection.removed = true
    }

    override suspend fun appPasswordInventory(
        role: StalwartRoutingActorRole,
    ): Set<String> {
        requireOpen()
        return requireInventory(actor(role).actor.mailAccount())
            .reserved
            .map(StalwartReservedCredential::credentialId)
            .toSet()
    }

    override suspend fun revokedAuthenticationStatus(
        role: StalwartRoutingActorRole,
    ): Int {
        requireOpen()
        val connection = actor(role)
        require(connection.removed) {
            "Routing AppPassword was not revoked"
        }
        val credential = connection.takeRevocationCredential()
        val authenticationProbe = GateJmapClient(
            profile = lifecycleProfile,
            credential = credential,
            transport = transport,
        )
        return authenticationProbe.use {
            try {
                it.discoverSession()
            } catch (failure: GateJmapException) {
                val status = (
                    failure.kind as? GateJmapFailure.HttpStatus
                    )?.status
                if (status == 401 || status == 403) {
                    return status
                }
                throw failure
            }
            throw IllegalStateException(
                "Revoked routing AppPassword still authenticated",
            )
        }
    }

    override suspend fun readinessPreflight(
        role: StalwartRoutingActorRole,
    ): StalwartRoutingReadinessEvidence {
        requireOpen()
        val connection = actor(role)
        require(connection.removed) {
            "Routing readiness ran before AppPassword revocation"
        }
        val before = mailTransport.snapshot()
        require(
            service.acquireMailLease(connection.actor.mailAccount()) ==
                StalwartMailLeaseAcquireResult.Unavailable(
                    StalwartMailLeaseUnavailableReason.NotReady,
                ),
        ) {
            "Removed routing Account unexpectedly reacquired mail access"
        }
        val projectedState = readinessPreflight.requireUnavailable(
            connection.actor.mailAccount(),
        )
        val after = mailTransport.snapshot()
        val uploadCalls = after.uploadCalls - before.uploadCalls
        val submissionCalls =
            after.submissionCalls - before.submissionCalls
        require(uploadCalls == 0 && submissionCalls == 0) {
            "Routing readiness dispatched mail before enrollment"
        }
        require(
            projectedState ==
                StalwartMailAccessState.EnrollmentRequired,
        ) {
            "Routing readiness did not require enrollment"
        }
        return StalwartRoutingReadinessEvidence(
            projectedState = projectedState,
            submissionCalls = submissionCalls,
            uploadCalls = uploadCalls,
        )
    }

    override suspend fun cleanup() {
        if (closed) return
        var failure: Throwable? = null

        suspend fun attempt(block: suspend () -> Unit) {
            try {
                block()
            } catch (cleanup: Throwable) {
                failure?.addSuppressed(cleanup) ?: run { failure = cleanup }
            }
        }

        attempt { cleanupMailArtifacts() }
        actors.values.forEach { connection ->
            attempt {
                connection.releaseMailAccess()
                removeAndVerify(connection.actor.mailAccount())
                connection.removed = true
            }
        }
        attempt { requireDurableStoreEmpty() }
        attempt {
            val global = when (val result = management.globalInventory()) {
                is StalwartRemoteRead.Available -> result.value
                StalwartRemoteRead.Unavailable ->
                    throw IllegalStateException(
                        "Routing global credential inventory was unavailable",
                    )
            }
            require(global.reserved.isEmpty()) {
                "Owned routing AppPassword remained after cleanup"
            }
        }
        failure?.let { throw it }
    }

    override fun close() {
        if (closed) return
        closed = true
        actors.values.forEach(RoutingActorConnection::close)
        actors.clear()
        managementClient.close()
        store.close()
        (transport as? AutoCloseable)?.close()
    }

    private suspend fun findSenderMailbox(
        sender: RoutingActorConnection,
    ): String {
        val payload = methodPayload(
            sender.appClient.call(
                methodName = "Mailbox/get",
                arguments = buildJsonObject {
                    put("accountId", sender.actor.accountId)
                    put("ids", JsonNull)
                    put(
                        "properties",
                        strings("id", "role"),
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Mailbox/get",
        )
        require(payload.requiredArray("notFound").isEmpty()) {
            "Routing Mailbox/get returned missing IDs"
        }
        val candidates = payload.requiredArray("list")
            .map {
                it as? JsonObject ?: throw IllegalArgumentException(
                    "Routing Mailbox/get result is malformed",
                )
            }
            .mapNotNull { mailbox ->
                val role = mailbox.optionalString("role")
                if (role == "drafts" || role == "inbox") {
                    role to mailbox.requiredSafeId("id")
                } else {
                    null
                }
            }
        return candidates.firstOrNull { it.first == "drafts" }?.second
            ?: candidates.firstOrNull { it.first == "inbox" }?.second
            ?: throw IllegalStateException(
                "Routing sender has no drafts or inbox Mailbox",
            )
    }

    private suspend fun findSenderIdentity(
        sender: RoutingActorConnection,
    ): String {
        val payload = methodPayload(
            sender.appClient.call(
                methodName = "Identity/get",
                arguments = buildJsonObject {
                    put("accountId", sender.actor.accountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "email"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Identity/get",
        )
        require(payload.requiredArray("notFound").isEmpty()) {
            "Routing Identity/get returned missing IDs"
        }
        val matches = payload.requiredArray("list")
            .map {
                it as? JsonObject ?: throw IllegalArgumentException(
                    "Routing Identity/get result is malformed",
                )
            }
            .filter {
                it.requiredString("email") == sender.actor.address
            }
        require(matches.size == 1) {
            "Routing sender Identity is not unique"
        }
        return matches.single().requiredSafeId("id")
    }

    private suspend fun importMessage(
        sender: RoutingActorConnection,
        mailboxId: String,
        recipient: String,
        subject: String,
        messageId: String,
    ): String {
        val message = buildString {
            append("From: <")
            append(sender.actor.address)
            append(">\r\nTo: <")
            append(recipient)
            append(">\r\nDate: Tue, 28 Jul 2026 12:34:56 +0000\r\n")
            append("Message-ID: ")
            append(messageId)
            append("\r\nSubject: ")
            append(subject)
            append("\r\nContent-Type: text/plain; charset=utf-8\r\n")
            append("\r\nmail-sandbox routing proof ")
            append(request.invocationId)
            append("\r\n")
        }
        val upload = methodPayload(
            sender.appClient.call(
                methodName = "Blob/upload",
                arguments = buildJsonObject {
                    put("accountId", sender.actor.accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                "routing-blob",
                                buildJsonObject {
                                    put(
                                        "data",
                                        buildJsonArray {
                                            add(
                                                buildJsonObject {
                                                    put(
                                                        "data:asText",
                                                        message,
                                                    )
                                                },
                                            )
                                        },
                                    )
                                    put("type", "message/rfc822")
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Blob/upload",
        )
        requireNoCreateFailures(upload, "Blob/upload")
        val createdBlob = upload.requiredObject("created")
            .requiredObject("routing-blob")
        require(createdBlob.requiredString("type") == "message/rfc822") {
            "Routing Blob/upload returned the wrong media type"
        }
        val blobId = createdBlob.requiredSafeId("id")
        val imported = methodPayload(
            sender.appClient.call(
                methodName = "Email/import",
                arguments = buildJsonObject {
                    put("accountId", sender.actor.accountId)
                    put(
                        "emails",
                        buildJsonObject {
                            put(
                                "routing-email",
                                buildJsonObject {
                                    put("blobId", blobId)
                                    put(
                                        "mailboxIds",
                                        buildJsonObject {
                                            put(mailboxId, true)
                                        },
                                    )
                                    put(
                                        "keywords",
                                        buildJsonObject {
                                            put("\$draft", true)
                                            put("\$seen", true)
                                        },
                                    )
                                    put(
                                        "receivedAt",
                                        Instant.now().toString(),
                                    )
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Email/import",
        )
        requireNoCreateFailures(imported, "Email/import")
        return imported.requiredObject("created")
            .requiredObject("routing-email")
            .requiredSafeId("id")
    }

    private suspend fun createSubmission(
        sender: RoutingActorConnection,
        emailId: String,
        identityId: String,
        recipient: String,
    ): String {
        val payload = methodPayload(
            sender.appClient.call(
                methodName = "EmailSubmission/set",
                arguments = buildJsonObject {
                    put("accountId", sender.actor.accountId)
                    put(
                        "create",
                        buildJsonObject {
                            put(
                                "routing-submission",
                                buildJsonObject {
                                    put("emailId", emailId)
                                    put("identityId", identityId)
                                    put(
                                        "envelope",
                                        buildJsonObject {
                                            put(
                                                "mailFrom",
                                                buildJsonObject {
                                                    put(
                                                        "email",
                                                        sender.actor.address,
                                                    )
                                                },
                                            )
                                            put(
                                                "rcptTo",
                                                buildJsonArray {
                                                    add(
                                                        buildJsonObject {
                                                            put(
                                                                "email",
                                                                recipient,
                                                            )
                                                        },
                                                    )
                                                },
                                            )
                                        },
                                    )
                                },
                            )
                        },
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "EmailSubmission/set",
        )
        requireNoCreateFailures(payload, "EmailSubmission/set")
        return payload.requiredObject("created")
            .requiredObject("routing-submission")
            .requiredSafeId("id")
    }

    private suspend fun submissionOutcome(
        sender: RoutingActorConnection,
        probe: StalwartRoutingProbeSpec,
        submissionId: String,
    ): JsonObject {
        val payload = methodPayload(
            sender.appClient.call(
                methodName = "EmailSubmission/get",
                arguments = buildJsonObject {
                    put("accountId", sender.actor.accountId)
                    put("ids", strings(submissionId))
                    put(
                        "properties",
                        strings(
                            "id",
                            "undoStatus",
                            "deliveryStatus",
                        ),
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "EmailSubmission/get",
        )
        require(payload.requiredArray("notFound").isEmpty()) {
            "Routing EmailSubmission/get lost the created submission"
        }
        val list = payload.requiredArray("list")
        require(list.size == 1) {
            "Routing EmailSubmission/get returned the wrong object count"
        }
        val submission = list.single() as? JsonObject
            ?: throw IllegalArgumentException(
                "Routing EmailSubmission/get result is malformed",
            )
        require(submission.requiredSafeId("id") == submissionId) {
            "Routing EmailSubmission/get returned another submission"
        }
        return StalwartRoutingSubmissionNormalizer.normalize(
            probe = probe,
            submissionId = submissionId,
            undoStatus = submission.requiredString("undoStatus"),
            deliveryStatus = submission.requiredObject("deliveryStatus"),
        )
    }

    private suspend fun exactSubjectEmailIds(
        connection: RoutingActorConnection,
        subject: String,
    ): Set<String> {
        val payload = methodPayload(
            connection.appClient.call(
                methodName = "Email/query",
                arguments = buildJsonObject {
                    put("accountId", connection.actor.accountId)
                    put(
                        "filter",
                        buildJsonObject { put("subject", subject) },
                    )
                    put("sort", buildJsonArray {})
                    put("position", 0)
                    put("limit", MAXIMUM_MARKER_RESULTS)
                    put("calculateTotal", true)
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Email/query",
        )
        val ids = payload.requiredArray("ids").map {
            safeId(
                it.requiredStringValue("routing Email ID"),
                "routing Email ID",
            )
        }
        require(
            ids.size == ids.toSet().size &&
                payload.requiredInt("position") == 0 &&
                payload.requiredInt("total") == ids.size,
        ) {
            "Routing Email/query result is incomplete"
        }
        return ids.toSet()
    }

    private suspend fun relatedSubmissionIds(
        connection: RoutingActorConnection,
        emailIds: Set<String>,
    ): Set<String> {
        if (emailIds.isEmpty()) return emptySet()
        val payload = methodPayload(
            connection.appClient.call(
                methodName = "EmailSubmission/get",
                arguments = buildJsonObject {
                    put("accountId", connection.actor.accountId)
                    put("ids", JsonNull)
                    put("properties", strings("id", "emailId"))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "EmailSubmission/get",
        )
        require(payload.requiredArray("notFound").isEmpty()) {
            "Routing EmailSubmission inventory returned missing IDs"
        }
        return payload.requiredArray("list")
            .map {
                it as? JsonObject ?: throw IllegalArgumentException(
                    "Routing EmailSubmission inventory is malformed",
                )
            }
            .filter {
                it.requiredString("emailId") in emailIds
            }
            .map { it.requiredSafeId("id") }
            .toSet()
    }

    private suspend fun requireEmailMessageId(
        connection: RoutingActorConnection,
        emailId: String,
        subject: String,
        expectedMessageId: String,
    ) {
        val payload = methodPayload(
            connection.appClient.call(
                methodName = "Email/get",
                arguments = buildJsonObject {
                    put("accountId", connection.actor.accountId)
                    put("ids", strings(emailId))
                    put(
                        "properties",
                        strings("id", "subject", "messageId"),
                    )
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            "Email/get",
        )
        require(payload.requiredArray("notFound").isEmpty()) {
            "Routing Email/get lost the arrived Email"
        }
        val list = payload.requiredArray("list")
        require(list.size == 1) {
            "Routing Email/get returned the wrong object count"
        }
        val email = list.single() as? JsonObject
            ?: throw IllegalArgumentException(
                "Routing Email/get result is malformed",
            )
        val expectedBareMessageId = expectedMessageId
            .removePrefix("<")
            .removeSuffix(">")
        require(
            email.requiredSafeId("id") == emailId &&
                email.requiredString("subject") == subject &&
                email.requiredArray("messageId")
                    .map {
                        it.requiredStringValue(
                            "routing Message-ID",
                        )
                    } == listOf(expectedBareMessageId),
        ) {
            "Routing arrival did not match the exact Message-ID"
        }
    }

    private suspend fun destroyObject(
        connection: RoutingActorConnection,
        methodName: String,
        id: String,
    ) {
        val payload = methodPayload(
            connection.appClient.call(
                methodName = methodName,
                arguments = buildJsonObject {
                    put("accountId", connection.actor.accountId)
                    put("destroy", strings(id))
                },
                capabilities = MAIL_CAPABILITIES,
            ),
            methodName,
        )
        val destroyed = payload.optionalArray("destroyed")
            .map {
                it.requiredStringValue("destroyed routing object ID")
            }
        val notDestroyed = payload.optionalObject("notDestroyed")
        if (destroyed == listOf(id)) {
            require(notDestroyed.isEmpty()) {
                "Routing artifact cleanup returned conflicting outcomes"
            }
            return
        }
        val failed = notDestroyed[id]?.let {
            it as? JsonObject ?: throw IllegalArgumentException(
                "Routing artifact cleanup failure is malformed",
            )
        }
        require(
            destroyed.isEmpty() &&
                notDestroyed.keys == setOf(id) &&
                failed?.requiredString("type") == "notFound",
        ) {
            "Routing artifact cleanup was not definitive"
        }
    }

    private fun methodPayload(
        response: JsonObject,
        expectedMethod: String,
    ): JsonObject {
        val responses = response["methodResponses"] as? JsonArray
            ?: throw IllegalArgumentException(
                "Routing JMAP response omitted methodResponses",
            )
        require(responses.size == 1) {
            "Routing JMAP response count is invalid"
        }
        val tuple = responses.single() as? JsonArray
            ?: throw IllegalArgumentException(
                "Routing JMAP response tuple is malformed",
            )
        require(
            tuple.size == 3 &&
                tuple[0].requiredStringValue("JMAP method") ==
                expectedMethod,
        ) {
            "Routing JMAP response method is invalid"
        }
        return tuple[1] as? JsonObject
            ?: throw IllegalArgumentException(
                "Routing JMAP response payload is malformed",
            )
    }

    private fun requireNoCreateFailures(
        payload: JsonObject,
        operation: String,
    ) {
        val notCreated = payload.requiredObject("notCreated")
        val created = payload.requiredObject("created")
        require(
            notCreated.isEmpty() && created.size == 1,
        ) {
            "$operation did not create exactly one routing object"
        }
    }

    private fun actor(
        role: StalwartRoutingActorRole,
    ): RoutingActorConnection =
        actors[role] ?: throw IllegalStateException(
            "Routing ${role.value} is not enrolled",
        )

    private fun createManagementClient(): GateJmapClient {
        val runtimeSecrets = StalwartRuntimeSecretLoader(
            StalwartRuntimeSecretPaths.production(
                request.dashboardProjectRoot,
            ),
        ).load()
        return runtimeSecrets.use { secrets ->
            require(
                secrets.protectedAccountIds ==
                    setOf(input.managementAccountId),
            ) {
                "Routing management protection did not match its input"
            }
            val credential = secrets.withManagementApiKey { bytes ->
                val chars = bytes.toRoutingAsciiChars()
                try {
                    GateCredential.bearer(chars)
                } finally {
                    chars.fill('\u0000')
                }
            }
            try {
                GateJmapClient(
                    profile = lifecycleProfile,
                    credential = credential,
                    transport = transport,
                )
            } catch (failure: Throwable) {
                credential.close()
                throw failure
            }
        }
    }

    private suspend fun requireInventory(
        account: StalwartMailAccount,
    ): StalwartReservedInventory =
        when (val result = management.inventory(account.accountId)) {
            is StalwartRemoteRead.Available -> result.value.also {
                require(it.accountId == account.accountId) {
                    "Routing credential inventory belonged to another Account"
                }
            }
            StalwartRemoteRead.Unavailable ->
                throw IllegalStateException(
                    "Routing credential inventory was unavailable",
                )
        }

    private suspend fun removeAndVerify(account: StalwartMailAccount) {
        requireCompletedState(
            result = service.remove(account),
            expected = StalwartMailAccessState.EnrollmentRequired,
            operation = "Routing removal",
        )
        val inventory = requireInventory(account)
        require(
            inventory.reserved.isEmpty() &&
                inventory.appPasswordCount == 0,
        ) {
            "Routing removal credential inventory was not empty"
        }
    }

    private fun requireCompletedState(
        result: StalwartMailAccessResult,
        expected: StalwartMailAccessState,
        operation: String,
    ) {
        val completed = result as? StalwartMailAccessResult.Completed
            ?: throw IllegalStateException("$operation did not complete")
        require(completed.projection.state == expected) {
            "$operation projected another state"
        }
    }

    private fun requireDurableStoreEmpty() {
        when (val loaded = store.load()) {
            is CredentialStoreLoadResult.Available ->
                loaded.snapshot.use { snapshot ->
                    require(snapshot.records.isEmpty()) {
                        "Routing encrypted credential snapshot was not empty"
                    }
                }
            CredentialStoreLoadResult.StoreUnavailable ->
                throw IllegalStateException(
                    "Routing encrypted credential snapshot was unavailable",
                )
        }
    }

    private fun StalwartRoutingInputActor.mailAccount():
        StalwartMailAccount =
        StalwartMailAccount(
            accountId = accountId,
            address = address,
        )

    private fun ByteArray.toRoutingAsciiChars(): CharArray =
        CharArray(size).also { output ->
            try {
                forEachIndexed { index, value ->
                    val unsigned = value.toInt() and 0xff
                    require(unsigned in 1..0x7f) {
                        "Routing credential was not ASCII"
                    }
                    output[index] = unsigned.toChar()
                }
            } catch (failure: Throwable) {
                output.fill('\u0000')
                throw failure
            }
        }

    private fun requireActorSession(
        session: GateJmapSession,
        actor: StalwartRoutingInputActor,
    ) {
        require(
            session.apiUrl == lifecycleProfile.apiUrl &&
                session.primaryAccountId == actor.accountId &&
                session.username == actor.address,
        ) {
            "Routing credential authenticated another Account"
        }
    }

    private fun strings(vararg values: String): JsonArray =
        JsonArray(values.map(::JsonPrimitive))

    private fun requireOpen() {
        check(!closed) { "Routing mail remote is closed" }
    }

    private class RoutingActorConnection(
        val role: StalwartRoutingActorRole,
        val actor: StalwartRoutingInputActor,
        lease: StalwartMailCredentialLease,
        appClient: GateJmapClient,
        revocationCredential: GateCredential,
        val credentialId: String,
    ) : AutoCloseable {
        private var lease: StalwartMailCredentialLease? = lease
        private var ownedAppClient: GateJmapClient? = appClient
        private var revocationCredential: GateCredential? =
            revocationCredential
        var removed = false

        val appClient: GateJmapClient
            get() = checkNotNull(ownedAppClient) {
                "Routing mail client is no longer leased"
            }

        fun releaseMailAccess() {
            ownedAppClient?.close()
            ownedAppClient = null
            lease?.close()
            lease = null
        }

        fun takeRevocationCredential(): GateCredential {
            val credential = revocationCredential
                ?: throw IllegalStateException(
                    "Routing revocation credential is unavailable",
                )
            revocationCredential = null
            return credential
        }

        override fun close() {
            releaseMailAccess()
            revocationCredential?.close()
            revocationCredential = null
        }
    }

    private companion object {
        val MAIL_CAPABILITIES = listOf(
            GateJmapCapability.CORE,
            GateJmapCapability.MAIL,
            GateJmapCapability.SUBMISSION,
            GateJmapCapability.BLOB,
        )
        const val SUBMISSION_STATUS_ATTEMPTS = 25
        const val SUBMISSION_STATUS_DELAY_MILLIS = 200L
        const val ARRIVAL_ATTEMPTS = 50
        const val ARRIVAL_DELAY_MILLIS = 200L
        const val MAXIMUM_MARKER_RESULTS = 10
    }
}

internal class StalwartRoutingProofCli(
    private val workflowFactory: StalwartRoutingProofWorkflowFactory,
    private val clock: () -> Instant = Instant::now,
) {
    suspend fun execute(
        args: Array<String>,
        stdout: PrintStream,
        stderr: PrintStream,
    ): Int {
        var workflow: StalwartRoutingProofWorkflow? = null
        return try {
            val arguments = StalwartRoutingProofArguments.parse(args)
            val request = StalwartRoutingProofRequest(
                dashboardProjectRoot = arguments.dashboardProjectRoot,
                invocationId = arguments.invocationId,
                endpointProfile = arguments.endpointProfile,
                paths = arguments.paths,
            )
            workflow = workflowFactory.create(request)
            val evidence = workflow.prove(request)
            val payload = StalwartRoutingProofValidator.payload(
                invocationId = arguments.invocationId,
                provenAt = clock(),
                evidence = evidence,
            )
            stdout.print(StalwartRoutingCanonicalJson.encode(payload))
            stdout.print('\n')
            stdout.flush()
            0
        } catch (cancellation: CancellationException) {
            throw cancellation
        } catch (_: Throwable) {
            stderr.print("Stalwart routing verifier failed\n")
            stderr.flush()
            1
        } finally {
            runCatching { workflow?.close() }
        }
    }
}

internal object StalwartRoutingProofValidator {
    fun payload(
        invocationId: String,
        provenAt: Instant,
        evidence: StalwartRoutingVerifierEvidence,
    ): JsonObject {
        require(INVOCATION_ID.matches(invocationId)) {
            "Routing invocation ID is invalid"
        }
        require(evidence.serverVersion == SERVER_VERSION) {
            "Routing server version is invalid"
        }
        val managementAccountId = safeId(
            evidence.managementAccountId,
            "management Account ID",
        )
        val managementCredentialId = safeId(
            evidence.managementCredentialId,
            "management credential ID",
        )
        val sender = actor(
            value = evidence.sender,
            role = "sender",
            invocationId = invocationId,
        )
        val recipient = actor(
            value = evidence.recipient,
            role = "recipient",
            invocationId = invocationId,
        )
        require(
            setOf(
                managementAccountId,
                evidence.sender.accountId,
                evidence.recipient.accountId,
            ).size == 3,
        ) {
            "Routing actors must use disposable Accounts"
        }
        require(
            evidence.sender.appPasswordCredentialId !=
                evidence.recipient.appPasswordCredentialId,
        ) {
            "Routing AppPassword IDs are not distinct"
        }
        val expectedMessageId =
            "<mail-sandbox-routing-$invocationId@local.test>"
        require(evidence.messageId == expectedMessageId) {
            "Routing Message-ID is invalid"
        }
        val probes = probes(
            value = evidence.probes,
            invocationId = invocationId,
            recipient = evidence.recipient,
            messageId = expectedMessageId,
        )
        val removal = accessRemoval(
            value = evidence.recipientAccessRemoved,
            credentialId = evidence.recipient.appPasswordCredentialId,
        )
        return buildJsonObject {
            put(
                "actors",
                buildJsonObject {
                    put("recipient", recipient)
                    put("sender", sender)
                },
            )
            put(
                "bootstrap_proof",
                validateBootstrapProof(evidence.bootstrapProof),
            )
            put("invocation_id", invocationId)
            put("management_account_id", managementAccountId)
            put("management_credential_id", managementCredentialId)
            put("message_id", expectedMessageId)
            put(
                "preserved_objects_sha256",
                requireSha256(
                    evidence.preservedObjectsSha256,
                    "preserved object digest",
                ),
            )
            put("probes", probes)
            put(
                "proven_at",
                provenAt.truncatedTo(ChronoUnit.SECONDS).toString(),
            )
            put("recipient_access_removed", removal)
            put("schema", VERIFIER_SCHEMA)
            put("server_version", SERVER_VERSION)
        }
    }

    private fun actor(
        value: StalwartRoutingActorEvidence,
        role: String,
        invocationId: String,
    ): JsonObject {
        val expectedAddress =
            "dashboard-routing-$role-$invocationId@local.test"
        require(value.address == expectedAddress) {
            "Routing $role address is invalid"
        }
        return buildJsonObject {
            put("account_id", safeId(value.accountId, "$role Account ID"))
            put("address", expectedAddress)
            put(
                "app_password_credential_id",
                safeId(
                    value.appPasswordCredentialId,
                    "$role AppPassword ID",
                ),
            )
        }
    }

    private fun probes(
        value: Map<String, JsonObject>,
        invocationId: String,
        recipient: StalwartRoutingActorEvidence,
        messageId: String,
    ): JsonObject {
        require(value.keys == PROBE_NAMES) {
            "Routing probe inventory is invalid"
        }
        val registered = registeredProbe(
            value = value.getValue("registered_local"),
            recipient = recipient,
            messageId = messageId,
        )
        val normalized = linkedMapOf(
            "external" to rejectionProbe(
                value = value.getValue("external"),
                name = "external",
                recipient =
                    "dashboard-routing-$invocationId@example.invalid",
                enhancedStatus = "5.1.2",
            ),
            "protected_exact" to rejectionProbe(
                value = value.getValue("protected_exact"),
                name = "protected exact",
                recipient = MANAGEMENT_ADDRESS,
                enhancedStatus = "5.7.1",
            ),
            "protected_subaddress" to rejectionProbe(
                value = value.getValue("protected_subaddress"),
                name = "protected subaddress",
                recipient =
                    "dashboard-management+routing-$invocationId@local.test",
                enhancedStatus = "5.7.1",
            ),
            "registered_local" to registered,
            "unregistered_local" to rejectionProbe(
                value = value.getValue("unregistered_local"),
                name = "unregistered local",
                recipient =
                    "dashboard-routing-missing-$invocationId@local.test",
                enhancedStatus = "5.1.2",
            ),
        )
        val submissionIds = normalized.values.map {
            it.requiredString("submission_id")
        }
        require(submissionIds.size == submissionIds.toSet().size) {
            "Routing submission IDs are not distinct"
        }
        return JsonObject(normalized)
    }

    private fun registeredProbe(
        value: JsonObject,
        recipient: StalwartRoutingActorEvidence,
        messageId: String,
    ): JsonObject {
        require(
            value.keys == setOf(
                "arrival",
                "delivery_status",
                "enhanced_status",
                "queue_accepted",
                "recipient",
                "smtp_code",
                "submission_created",
                "submission_id",
                "undo_status",
            ),
        ) {
            "Registered-local routing probe is invalid"
        }
        val arrival = value.requiredObject("arrival")
        require(
            arrival.keys == setOf(
                "account_id",
                "matching_email_ids",
                "message_id",
            ),
        ) {
            "Registered-local arrival is invalid"
        }
        val matchingIds = arrival.requiredArray("matching_email_ids")
        require(matchingIds.size == 1) {
            "Registered-local arrival is not unique"
        }
        val emailId = matchingIds.single().requiredStringValue(
            "registered-local Email ID",
        )
        val expected = buildJsonObject {
            put(
                "arrival",
                buildJsonObject {
                    put("account_id", recipient.accountId)
                    put(
                        "matching_email_ids",
                        buildJsonArray { add(JsonPrimitive(safeId(emailId, "Email ID"))) },
                    )
                    put("message_id", messageId)
                },
            )
            put("delivery_status", "unknown")
            put("enhanced_status", "2.1.5")
            put("queue_accepted", true)
            put("recipient", recipient.address)
            put("smtp_code", 250)
            put("submission_created", true)
            put(
                "submission_id",
                safeId(
                    value.requiredString("submission_id"),
                    "registered-local submission ID",
                ),
            )
            put("undo_status", "final")
        }
        require(value == expected) {
            "Registered-local routing proof is not exact"
        }
        return expected
    }

    private fun rejectionProbe(
        value: JsonObject,
        name: String,
        recipient: String,
        enhancedStatus: String,
    ): JsonObject {
        require(
            value.keys == setOf(
                "delivery_status",
                "enhanced_status",
                "queue_accepted",
                "recipient",
                "smtp_code",
                "submission_created",
                "submission_id",
                "undo_status",
            ),
        ) {
            "$name routing probe is invalid"
        }
        val expected = buildJsonObject {
            put("delivery_status", "no")
            put("enhanced_status", enhancedStatus)
            put("queue_accepted", false)
            put("recipient", recipient)
            put("smtp_code", 550)
            put("submission_created", true)
            put(
                "submission_id",
                safeId(
                    value.requiredString("submission_id"),
                    "$name submission ID",
                ),
            )
            put("undo_status", "pending")
        }
        require(value == expected) {
            "$name routing probe did not reject safely"
        }
        return expected
    }

    private fun accessRemoval(
        value: JsonObject,
        credentialId: String,
    ): JsonObject {
        require(
            value.keys == setOf(
                "authentication_status",
                "credential_id",
                "projected_state",
                "readiness_preflight",
            ),
        ) {
            "Routing recipient access removal is invalid"
        }
        val authenticationStatus = value.requiredInt("authentication_status")
        require(authenticationStatus == 401 || authenticationStatus == 403) {
            "Revoked recipient authentication was inconclusive"
        }
        val expected = buildJsonObject {
            put("authentication_status", authenticationStatus)
            put("credential_id", credentialId)
            put("projected_state", "enrollmentRequired")
            put(
                "readiness_preflight",
                buildJsonObject {
                    put("submission_calls", 0)
                    put("upload_calls", 0)
                },
            )
        }
        require(value == expected) {
            "Routing readiness was not blocked before mail calls"
        }
        return expected
    }

    private val INVOCATION_ID = Regex("[0-9a-f]{32}")
    private val PROBE_NAMES = setOf(
        "external",
        "protected_exact",
        "protected_subaddress",
        "registered_local",
        "unregistered_local",
    )
}

private fun validateBootstrapProof(value: JsonObject): JsonObject {
    require(value.keys == setOf("identity", "name", "sha256", "size")) {
        "Bootstrap proof metadata is invalid"
    }
    val identity = value.requiredArray("identity")
    require(
        identity.size == 6 &&
            identity.all { item ->
                val primitive = item as? JsonPrimitive
                primitive != null &&
                    !primitive.isString &&
                    primitive.longOrNull?.let { it >= 0 } == true
            },
    ) {
        "Bootstrap proof identity is invalid"
    }
    require(
        value.requiredString("name") == "bootstrap-proof.json" &&
            value.requiredInt("size") >= 0,
    ) {
        "Bootstrap proof metadata is invalid"
    }
    value.requiredSha256("sha256")
    return value
}

private fun readOwnerOnlyRegular(
    root: Path,
    path: Path,
    maximumBytes: Int,
    label: String,
): ByteArray {
    require(
        root.isAbsolute &&
            path.isAbsolute &&
            path.normalize() == path &&
            path.startsWith(root),
    ) {
        "$label path is invalid"
    }
    var current = root
    root.relativize(path).forEach { segment ->
        current = current.resolve(segment)
        require(!Files.isSymbolicLink(current)) {
            "$label path contains a symbolic link"
        }
    }
    val attributes = runCatching {
        Files.readAttributes(
            path,
            PosixFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
    }.getOrElse {
        throw IllegalArgumentException("$label is unavailable")
    }
    require(
        attributes.isRegularFile &&
            attributes.permissions() == OWNER_READ_WRITE &&
            attributes.size() in 1..maximumBytes.toLong() &&
            Files.getAttribute(
                path,
                "unix:nlink",
                LinkOption.NOFOLLOW_LINKS,
            ) == 1,
    ) {
        "$label has unsafe type, mode, links, or size"
    }
    val content = Files.readAllBytes(path)
    require(
        content.size.toLong() == attributes.size() &&
            content.size <= maximumBytes,
    ) {
        "$label changed while reading"
    }
    return content
}

private fun JsonObject.requiredObject(name: String): JsonObject =
    this[name] as? JsonObject
        ?: throw IllegalArgumentException("$name is not an object")

private fun JsonObject.requiredArray(name: String): JsonArray =
    this[name] as? JsonArray
        ?: throw IllegalArgumentException("$name is not an array")

private fun JsonObject.optionalArray(name: String): JsonArray =
    when (val value = this[name]) {
        null -> JsonArray(emptyList())
        is JsonArray -> value
        else -> throw IllegalArgumentException("$name is not an array")
    }

private fun JsonObject.optionalObject(name: String): JsonObject =
    when (val value = this[name]) {
        null -> JsonObject(emptyMap())
        is JsonObject -> value
        else -> throw IllegalArgumentException("$name is not an object")
    }

private fun JsonObject.requiredString(name: String): String =
    this[name].requiredStringValue(name)

private fun JsonObject.optionalString(name: String): String? =
    when (val value = this[name]) {
        null, JsonNull -> null
        is JsonPrimitive -> {
            require(value.isString) { "$name is not a string" }
            value.content
        }

        else -> throw IllegalArgumentException("$name is not a string")
    }

private fun JsonElement?.requiredStringValue(label: String): String {
    val primitive = this as? JsonPrimitive
    require(primitive != null && primitive.isString) {
        "$label is not a string"
    }
    return primitive.content
}

private fun JsonObject.requiredInt(name: String): Int {
    val primitive = this[name] as? JsonPrimitive
    require(
        primitive != null &&
            !primitive.isString &&
            primitive.intOrNull != null,
    ) {
        "$name is not an integer"
    }
    return requireNotNull(primitive.intOrNull)
}

private fun JsonObject.requiredSafeId(name: String): String =
    safeId(requiredString(name), name)

private fun JsonObject.requiredSha256(name: String): String =
    requireSha256(requiredString(name), name)

private fun safeId(value: String, label: String): String {
    require(SAFE_ID.matches(value)) {
        "$label is invalid"
    }
    return value
}

private fun requireSha256(value: String, label: String): String {
    require(SHA256.matches(value)) {
        "$label is invalid"
    }
    return value
}

private val OWNER_READ_WRITE = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
)
private val SAFE_ID = Regex("[A-Za-z0-9_-]{1,255}")
private val SHA256 = Regex("[0-9a-f]{64}")
private const val INPUT_SCHEMA =
    "mail-sandbox.stalwart-v016-routing-input.v1"
private const val VERIFIER_SCHEMA =
    "mail-sandbox.stalwart-v016-routing-verifier.v1"
private const val SERVER_VERSION = "0.16.16"
private const val MANAGEMENT_ADDRESS =
    "dashboard-management@local.test"

fun main(args: Array<String>) {
    val exitCode = runBlocking {
        StalwartRoutingProofCli(
            workflowFactory = StalwartRoutingProofWorkflowFactory {
                StalwartRoutingLiveWorkflow()
            },
        ).execute(
            args = args,
            stdout = System.out,
            stderr = System.err,
        )
    }
    if (exitCode != 0) {
        exitProcess(exitCode)
    }
}
