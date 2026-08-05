package mail.sandbox.dashboard.server.gate.stalwart

import java.io.BufferedReader
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

internal fun requireSingleJmapMethodPayload(
    response: JsonObject,
    expectedMethod: String,
): JsonObject {
    require(expectedMethod.isSafeGateOpaqueText()) {
        "Expected JMAP method is invalid"
    }
    val tuple = requireSingleJmapMethodTuple(response)
    if (tuple.method == "error") {
        val type = tuple.payload.requiredGateString("type")
        throw GateJmapException(
            kind = GateJmapFailure.MethodError(type),
            message = "JMAP method returned a typed error",
        )
    }
    if (tuple.method != expectedMethod) {
        invalidGateContractResponse("JMAP response method did not match the request")
    }
    return tuple.payload
}

internal fun buildEmailSetUpdateArguments(
    accountId: String,
    ifInState: String,
    updates: Map<String, JsonObject>,
): JsonObject {
    require(accountId.isSafeGateOpaqueText()) { "Email/set Account ID is invalid" }
    require(ifInState.isSafeGateOpaqueText()) { "Email/set state is invalid" }
    require(updates.size in 1..MAXIMUM_GATE_SET_UPDATES) {
        "Email/set update count is invalid"
    }
    updates.forEach { (emailId, patch) ->
        require(emailId.isSafeGateOpaqueText()) { "Email/set Email ID is invalid" }
        require(patch.isNotEmpty()) { "Email/set patch is empty" }
        require(patch.keys.all(String::isSafeGatePatchPath)) {
            "Email/set patch path is invalid"
        }
    }
    return buildJsonObject {
        put("accountId", accountId)
        put("ifInState", ifInState)
        put("update", JsonObject(updates))
    }
}

internal sealed interface GateEmailSetObjectOutcome {
    data object Updated : GateEmailSetObjectOutcome

    data class NotUpdated(
        val type: String,
    ) : GateEmailSetObjectOutcome
}

internal sealed interface GateEmailSetResponse {
    data class Applied(
        val oldState: String,
        val newState: String,
        val outcomes: Map<String, GateEmailSetObjectOutcome>,
    ) : GateEmailSetResponse {
        override fun toString(): String =
            "GateEmailSetResponse.Applied(" +
                "oldState=redacted, newState=redacted, outcomes=$outcomes)"
    }

    data class Conflict(
        val type: String,
    ) : GateEmailSetResponse
}

internal fun parseGateEmailSetResponse(
    response: JsonObject,
    expectedAccountId: String,
    requestedIds: Set<String>,
): GateEmailSetResponse.Applied {
    require(expectedAccountId.isSafeGateOpaqueText()) {
        "Expected Email/set Account ID is invalid"
    }
    require(requestedIds.size in 1..MAXIMUM_GATE_SET_UPDATES) {
        "Expected Email/set ID count is invalid"
    }
    require(requestedIds.all(String::isSafeGateOpaqueText)) {
        "Expected Email/set ID is invalid"
    }
    val payload = requireSingleJmapMethodPayload(
        response = response,
        expectedMethod = "Email/set",
    )
    if (payload.requiredGateString("accountId") != expectedAccountId) {
        invalidGateContractResponse("Email/set response belongs to another Account")
    }
    val oldState = payload.requiredGateString("oldState")
    val newState = payload.requiredGateString("newState")
    val updated = payload.optionalGateObject("updated")
    val notUpdated = payload.optionalGateObject("notUpdated")
    if (updated.keys.any(notUpdated::containsKey)) {
        invalidGateContractResponse("Email/set response contained contradictory outcomes")
    }
    val accountedIds = updated.keys + notUpdated.keys
    if (accountedIds != requestedIds) {
        invalidGateContractResponse("Email/set response did not account for the requested IDs")
    }
    updated.forEach { (_, value) ->
        if (value != JsonNull) {
            invalidGateContractResponse("Email/set updated outcome was malformed")
        }
    }
    val outcomes = linkedMapOf<String, GateEmailSetObjectOutcome>()
    requestedIds.forEach { id ->
        outcomes[id] = if (id in updated) {
            GateEmailSetObjectOutcome.Updated
        } else {
            val error = notUpdated[id] as? JsonObject
                ?: invalidGateContractResponse("Email/set notUpdated outcome was malformed")
            GateEmailSetObjectOutcome.NotUpdated(
                type = error.requiredGateString("type"),
            )
        }
    }
    return GateEmailSetResponse.Applied(
        oldState = oldState,
        newState = newState,
        outcomes = outcomes.toMap(),
    )
}

internal fun requireGateEmailSetConflict(
    failure: GateJmapException,
): GateEmailSetResponse.Conflict {
    val type = (failure.kind as? GateJmapFailure.MethodError)?.type
    if (type != "stateMismatch") throw failure
    return GateEmailSetResponse.Conflict(type)
}

internal class GateOwnedAccountLedger(
    val localPart: String,
    val domainId: String,
    baselineAccountIds: Set<String>,
) {
    private val baselineAccountIds = baselineAccountIds.toSet()
    private val mutableCleanupIds = linkedSetOf<String>()

    var createAttempted: Boolean = false
        private set

    val cleanupIds: Set<String>
        get() = mutableCleanupIds.toSet()

    init {
        require(SAFE_GATE_LOCAL_PART.matches(localPart)) {
            "Owned Account local part is invalid"
        }
        require(domainId.isSafeGateOpaqueText()) {
            "Owned Account Domain ID is invalid"
        }
        require(baselineAccountIds.all(String::isSafeGateOpaqueText)) {
            "Owned Account baseline ID is invalid"
        }
    }

    suspend fun <T> dispatchCreate(block: suspend () -> T): T {
        check(!createAttempted) { "Owned Account create was already dispatched" }
        createAttempted = true
        return block()
    }

    fun recordCreatedId(id: String) {
        check(createAttempted) { "Owned Account create was not dispatched" }
        requireOwnedCandidateId(id)
        mutableCleanupIds += id
    }

    fun reconcileCandidate(projection: JsonObject): Boolean {
        check(createAttempted) { "Owned Account create was not dispatched" }
        val name = projection.requiredLedgerString("name")
        if (name != localPart) return false
        val id = projection.requiredLedgerString("id")
        requireOwnedCandidateId(id)
        check(projection.requiredLedgerString("domainId") == domainId) {
            "Exact owned Account name collided with another Domain"
        }
        check(projection.requiredLedgerString("@type") == "User") {
            "Exact owned Account candidate is not a User"
        }
        mutableCleanupIds += id
        return true
    }

    fun requireSafeToDestroy(id: String, projection: JsonObject) {
        check(id in mutableCleanupIds) {
            "Account cleanup ID was not recorded by the owned ledger"
        }
        check(projection.requiredLedgerString("id") == id) {
            "Account cleanup projection ID did not match"
        }
        check(projection.requiredLedgerString("name") == localPart) {
            "Account cleanup projection name did not match"
        }
        check(projection.requiredLedgerString("domainId") == domainId) {
            "Account cleanup projection Domain did not match"
        }
        check(projection.requiredLedgerString("@type") == "User") {
            "Account cleanup projection is not a User"
        }
        requireOwnedCandidateId(id)
    }

    private fun requireOwnedCandidateId(id: String) {
        require(id.isSafeGateOpaqueText()) { "Owned Account ID is invalid" }
        check(id !in baselineAccountIds) {
            "Owned Account candidate existed in the baseline inventory"
        }
    }

    override fun toString(): String =
        "GateOwnedAccountLedger(localPart=$localPart, domainId=redacted, " +
            "createAttempted=$createAttempted, cleanupCount=${mutableCleanupIds.size})"
}

internal class GateMailArtifactLedger(
    val exactSubject: String,
    val exactMessageId: String,
    exactMailboxNames: Set<String>,
) {
    val exactMailboxNames: Set<String> = exactMailboxNames.toSet()
    private val normalizedMessageId = exactMessageId
        .removePrefix("<")
        .removeSuffix(">")
    private val mutableMailboxCleanupIds = linkedSetOf<String>()
    private val mutableEmailCleanupIds = linkedSetOf<String>()

    var mailboxCreateAttempted: Boolean = false
        private set
    var emailImportAttempted: Boolean = false
        private set

    val mailboxCleanupIds: Set<String>
        get() = mutableMailboxCleanupIds.toSet()
    val emailCleanupIds: Set<String>
        get() = mutableEmailCleanupIds.toSet()

    init {
        require(exactSubject.isSafeGateMarkerText()) {
            "Marker subject is invalid"
        }
        require(
            exactMessageId == "<$normalizedMessageId>" &&
                SAFE_GATE_MESSAGE_ID.matches(normalizedMessageId),
        ) {
            "Marker Message-ID is invalid"
        }
        require(exactMailboxNames.size in 1..MAXIMUM_GATE_MARKER_MAILBOXES) {
            "Marker mailbox name count is invalid"
        }
        require(exactMailboxNames.all(String::isSafeGateMarkerText)) {
            "Marker mailbox name is invalid"
        }
    }

    suspend fun <T> dispatchMailboxCreate(block: suspend () -> T): T {
        check(!mailboxCreateAttempted) { "Marker Mailbox create was already dispatched" }
        mailboxCreateAttempted = true
        return block()
    }

    suspend fun <T> dispatchEmailImport(block: suspend () -> T): T {
        check(!emailImportAttempted) { "Marker Email import was already dispatched" }
        emailImportAttempted = true
        return block()
    }

    fun recordMailboxId(id: String) {
        check(mailboxCreateAttempted) { "Marker Mailbox create was not dispatched" }
        require(id.isSafeGateOpaqueText()) { "Marker Mailbox ID is invalid" }
        mutableMailboxCleanupIds += id
    }

    fun recordEmailId(id: String) {
        check(emailImportAttempted) { "Marker Email import was not dispatched" }
        require(id.isSafeGateOpaqueText()) { "Marker Email ID is invalid" }
        mutableEmailCleanupIds += id
    }

    fun reconcileMailboxCandidate(id: String, name: String): Boolean {
        check(mailboxCreateAttempted) { "Marker Mailbox create was not dispatched" }
        if (name !in exactMailboxNames) return false
        recordMailboxId(id)
        return true
    }

    fun reconcileEmailCandidate(
        id: String,
        subject: String,
        messageIds: List<String>,
    ): Boolean {
        check(emailImportAttempted) { "Marker Email import was not dispatched" }
        if (subject != exactSubject || normalizedMessageId !in messageIds) return false
        recordEmailId(id)
        return true
    }

    override fun toString(): String =
        "GateMailArtifactLedger(marker=redacted, " +
            "mailboxCreateAttempted=$mailboxCreateAttempted, " +
            "emailImportAttempted=$emailImportAttempted, " +
            "mailboxCleanupCount=${mutableMailboxCleanupIds.size}, " +
            "emailCleanupCount=${mutableEmailCleanupIds.size})"
}

internal data class GateSmtpReply(
    val code: Int,
    val enhancedStatus: String?,
    internal val lines: List<String>,
) {
    override fun toString(): String =
        "GateSmtpReply(code=$code, enhancedStatus=$enhancedStatus, " +
            "lineCount=${lines.size}, text=redacted)"
}

internal sealed interface GateSmtpRecipientOutcome {
    val code: Int
    val enhancedStatus: String?

    data class Accepted(
        override val code: Int,
        override val enhancedStatus: String?,
    ) : GateSmtpRecipientOutcome

    data class TransientRejected(
        override val code: Int,
        override val enhancedStatus: String?,
    ) : GateSmtpRecipientOutcome

    data class PermanentRejected(
        override val code: Int,
        override val enhancedStatus: String?,
    ) : GateSmtpRecipientOutcome
}

internal sealed interface GateSmtpDeliveryOutcome {
    data class Accepted(
        val recipient: GateSmtpRecipientOutcome.Accepted,
        val queuedCode: Int,
        val queuedEnhancedStatus: String?,
    ) : GateSmtpDeliveryOutcome

    data class RecipientRejected(
        val rejection: GateSmtpRecipientOutcome,
    ) : GateSmtpDeliveryOutcome
}

internal fun GateSmtpReply.toRecipientOutcome(): GateSmtpRecipientOutcome =
    when (code) {
        250, 251 -> GateSmtpRecipientOutcome.Accepted(code, enhancedStatus)
        in 400..499 -> GateSmtpRecipientOutcome.TransientRejected(code, enhancedStatus)
        in 500..599 -> GateSmtpRecipientOutcome.PermanentRejected(code, enhancedStatus)
        else -> throw IllegalStateException("SMTP recipient response status was invalid")
    }

internal fun readBoundedGateSmtpReply(
    readLine: () -> String?,
): GateSmtpReply {
    val lines = mutableListOf<String>()
    var expectedCode: Int? = null
    repeat(MAXIMUM_GATE_SMTP_RESPONSE_LINES) {
        val line = readLine()
            ?: throw IllegalStateException("SMTP closed before a complete response")
        check(line.length in 4..MAXIMUM_GATE_SMTP_LINE_CHARS) {
            "SMTP returned a malformed response line"
        }
        val code = line.substring(0, 3).toIntOrNull()
            ?.takeIf { it in 100..599 }
            ?: throw IllegalStateException("SMTP returned an invalid response code")
        expectedCode?.let {
            check(code == it) { "SMTP multiline response changed its status code" }
        } ?: run {
            expectedCode = code
        }
        lines += line
        when (line[3]) {
            '-' -> Unit
            ' ' -> return GateSmtpReply(
                code = code,
                enhancedStatus = lines.asReversed()
                    .firstNotNullOfOrNull(::smtpEnhancedStatus),
                lines = lines.toList(),
            )
            else -> throw IllegalStateException(
                "SMTP returned an invalid multiline separator",
            )
        }
    }
    throw IllegalStateException("SMTP response exceeded its line bound")
}

internal interface GateSmtpWire : AutoCloseable {
    fun readLine(): String?

    fun write(bytes: ByteArray)
}

internal fun interface GateSmtpConnector {
    fun connect(): GateSmtpWire
}

internal class GateSmtpClient(
    private val connector: GateSmtpConnector,
) : AutoCloseable {
    private var closed = false

    fun send(
        username: String,
        secret: CharArray,
        envelopeFrom: String,
        envelopeRecipient: String,
        rawMessage: String,
    ): GateSmtpDeliveryOutcome {
        requireOpen()
        validateGateSmtpInputs(username, secret, envelopeFrom, envelopeRecipient)
        val framedMessage = frameGateSmtpData(rawMessage)
        return executeSmtpTransport {
            connector.connect().use { wire ->
                val recipient = authenticateAndAddress(
                    wire = wire,
                    username = username,
                    secret = secret,
                    envelopeFrom = envelopeFrom,
                    envelopeRecipient = envelopeRecipient,
                )
                if (recipient !is GateSmtpRecipientOutcome.Accepted) {
                    resetAndQuit(wire)
                    return@use GateSmtpDeliveryOutcome.RecipientRejected(recipient)
                }
                writeSmtpCommand(wire, "DATA")
                requireSmtpCode(readBoundedGateSmtpReply(wire::readLine), 354, "DATA")
                wire.write(framedMessage)
                val queued = readBoundedGateSmtpReply(wire::readLine)
                requireSmtpCode(queued, 250, "message queueing")
                quit(wire)
                GateSmtpDeliveryOutcome.Accepted(
                    recipient = recipient,
                    queuedCode = queued.code,
                    queuedEnhancedStatus = queued.enhancedStatus,
                )
            }
        }
    }

    fun probeRecipient(
        username: String,
        secret: CharArray,
        envelopeFrom: String,
        envelopeRecipient: String,
    ): GateSmtpRecipientOutcome {
        requireOpen()
        validateGateSmtpInputs(username, secret, envelopeFrom, envelopeRecipient)
        return executeSmtpTransport {
            connector.connect().use { wire ->
                val recipient = authenticateAndAddress(
                    wire = wire,
                    username = username,
                    secret = secret,
                    envelopeFrom = envelopeFrom,
                    envelopeRecipient = envelopeRecipient,
                )
                recipient
            }
        }
    }

    private fun authenticateAndAddress(
        wire: GateSmtpWire,
        username: String,
        secret: CharArray,
        envelopeFrom: String,
        envelopeRecipient: String,
    ): GateSmtpRecipientOutcome {
        requireSmtpCode(readBoundedGateSmtpReply(wire::readLine), 220, "greeting")
        writeSmtpCommand(wire, "EHLO gate0b.local.test")
        val ehlo = readBoundedGateSmtpReply(wire::readLine)
        requireSmtpCode(ehlo, 250, "EHLO")
        check(ehlo.lines.any(::advertisesPlainAuthentication)) {
            "SMTP gate did not advertise AUTH PLAIN"
        }
        writeSmtpAuthPlain(wire, username, secret)
        requireSmtpCode(
            readBoundedGateSmtpReply(wire::readLine),
            235,
            "AUTH PLAIN",
        )
        writeSmtpCommand(wire, "MAIL FROM:<$envelopeFrom>")
        requireSmtpCode(
            readBoundedGateSmtpReply(wire::readLine),
            250,
            "MAIL FROM",
        )
        writeSmtpCommand(wire, "RCPT TO:<$envelopeRecipient>")
        return readBoundedGateSmtpReply(wire::readLine).toRecipientOutcome()
    }

    private fun resetAndQuit(wire: GateSmtpWire) {
        writeSmtpCommand(wire, "RSET")
        requireSmtpCode(readBoundedGateSmtpReply(wire::readLine), 250, "RSET")
        quit(wire)
    }

    private fun quit(wire: GateSmtpWire) {
        writeSmtpCommand(wire, "QUIT")
        requireSmtpCode(readBoundedGateSmtpReply(wire::readLine), 221, "QUIT")
    }

    override fun close() {
        closed = true
    }

    private fun requireOpen() {
        check(!closed) { "Gate SMTP client is closed" }
    }

    override fun toString(): String = "GateSmtpClient(endpoint=disposable-gate, secrets=redacted)"

    companion object {
        fun disposableGate(): GateSmtpClient =
            GateSmtpClient(DisposableGateSmtpConnector)
    }
}

private object DisposableGateSmtpConnector : GateSmtpConnector {
    override fun connect(): GateSmtpWire {
        val socket = Socket()
        try {
            socket.connect(
                InetSocketAddress(GATE_SMTP_HOST, GATE_SMTP_PORT),
                GATE_SMTP_CONNECT_TIMEOUT_MILLIS,
            )
            socket.soTimeout = GATE_SMTP_READ_TIMEOUT_MILLIS
            return SocketGateSmtpWire(socket)
        } catch (failure: Throwable) {
            runCatching { socket.close() }
            throw failure
        }
    }
}

private class SocketGateSmtpWire(
    private val socket: Socket,
) : GateSmtpWire {
    private val reader: BufferedReader = socket.getInputStream()
        .bufferedReader(StandardCharsets.US_ASCII)
    private val output: OutputStream = socket.getOutputStream()

    override fun readLine(): String? = reader.readLine()

    override fun write(bytes: ByteArray) {
        output.write(bytes)
        output.flush()
    }

    override fun close() {
        socket.close()
    }
}

private fun frameGateSmtpData(rawMessage: String): ByteArray {
    requireGateRfc5322Headers(rawMessage)
    val raw = rawMessage.toByteArray(StandardCharsets.UTF_8)
    require(raw.size in 1..MAXIMUM_GATE_SMTP_MESSAGE_BYTES) {
        "SMTP message size is invalid"
    }
    require(raw.none { it == 0.toByte() }) { "SMTP message contains NUL" }
    var atLineStart = true
    val framed = ArrayList<Byte>(raw.size + 16)
    raw.forEachIndexed { index, byte ->
        when (byte) {
            '\r'.code.toByte() -> require(index + 1 < raw.size && raw[index + 1] == '\n'.code.toByte()) {
                "SMTP message contains a bare carriage return"
            }
            '\n'.code.toByte() -> require(index > 0 && raw[index - 1] == '\r'.code.toByte()) {
                "SMTP message contains a bare line feed"
            }
        }
        if (atLineStart && byte == '.'.code.toByte()) {
            framed += '.'.code.toByte()
        }
        framed += byte
        atLineStart = byte == '\n'.code.toByte()
    }
    if (
        raw.size < 2 ||
        raw[raw.lastIndex - 1] != '\r'.code.toByte() ||
        raw[raw.lastIndex] != '\n'.code.toByte()
    ) {
        framed += '\r'.code.toByte()
        framed += '\n'.code.toByte()
    }
    framed += '.'.code.toByte()
    framed += '\r'.code.toByte()
    framed += '\n'.code.toByte()
    return framed.toByteArray()
}

private fun requireGateRfc5322Headers(rawMessage: String) {
    val headerEnd = rawMessage.indexOf("\r\n\r\n")
    require(headerEnd > 0) { "SMTP message did not contain an RFC 5322 header block" }
    val headerNames = rawMessage.substring(0, headerEnd)
        .split("\r\n")
        .mapNotNull { line ->
            line.substringBefore(':', missingDelimiterValue = "")
                .takeIf(String::isNotEmpty)
                ?.lowercase()
        }
        .toSet()
    require(headerNames.containsAll(REQUIRED_GATE_MESSAGE_HEADERS)) {
        "SMTP message omitted a required header"
    }
}

private fun writeSmtpCommand(wire: GateSmtpWire, command: String) {
    require(command.isNotEmpty() && command.all { it.code in 32..126 }) {
        "SMTP command is invalid"
    }
    wire.write("$command\r\n".toByteArray(StandardCharsets.US_ASCII))
}

private fun writeSmtpAuthPlain(
    wire: GateSmtpWire,
    username: String,
    secret: CharArray,
) {
    val usernameBytes = username.toByteArray(StandardCharsets.US_ASCII)
    val secretBytes = ByteArray(secret.size) { index -> secret[index].code.toByte() }
    val challenge = ByteArray(usernameBytes.size + secretBytes.size + 2)
    var encoded = ByteArray(0)
    var command = ByteArray(0)
    try {
        usernameBytes.copyInto(challenge, destinationOffset = 1)
        secretBytes.copyInto(challenge, destinationOffset = usernameBytes.size + 2)
        encoded = Base64.getEncoder().encode(challenge)
        val prefix = "AUTH PLAIN ".toByteArray(StandardCharsets.US_ASCII)
        val suffix = "\r\n".toByteArray(StandardCharsets.US_ASCII)
        command = ByteArray(prefix.size + encoded.size + suffix.size)
        prefix.copyInto(command)
        encoded.copyInto(command, destinationOffset = prefix.size)
        suffix.copyInto(command, destinationOffset = prefix.size + encoded.size)
        wire.write(command)
    } finally {
        usernameBytes.fill(0)
        secretBytes.fill(0)
        challenge.fill(0)
        encoded.fill(0)
        command.fill(0)
    }
}

private fun validateGateSmtpInputs(
    username: String,
    secret: CharArray,
    envelopeFrom: String,
    envelopeRecipient: String,
) {
    require(SAFE_GATE_ADDRESS.matches(username)) { "SMTP username is invalid" }
    require(SAFE_GATE_ADDRESS.matches(envelopeFrom)) { "SMTP sender is invalid" }
    require(SAFE_GATE_ADDRESS.matches(envelopeRecipient)) { "SMTP recipient is invalid" }
    require(secret.isNotEmpty() && secret.all { it.code in 1..127 }) {
        "SMTP secret is absent or invalid"
    }
}

private fun requireSmtpCode(reply: GateSmtpReply, expected: Int, operation: String) {
    check(reply.code == expected) {
        "$operation failed with SMTP status ${reply.code}"
    }
}

private fun advertisesPlainAuthentication(line: String): Boolean {
    val capability = line.substring(4).trim().split(Regex(" +"))
    return capability.firstOrNull()?.equals("AUTH", ignoreCase = true) == true &&
        capability.drop(1).any { it.equals("PLAIN", ignoreCase = true) }
}

private fun smtpEnhancedStatus(line: String): String? =
    ENHANCED_SMTP_STATUS.find(line.substring(4))?.groupValues?.get(1)

private inline fun <T> executeSmtpTransport(block: () -> T): T =
    try {
        block()
    } catch (failure: IllegalArgumentException) {
        throw failure
    } catch (failure: IllegalStateException) {
        throw failure
    } catch (failure: Exception) {
        throw IllegalStateException(
            "Disposable gate SMTP transport failed (${failure::class.simpleName})",
        )
    }

private data class SingleJmapMethodTuple(
    val method: String,
    val payload: JsonObject,
)

private fun requireSingleJmapMethodTuple(response: JsonObject): SingleJmapMethodTuple {
    val methodResponses = response["methodResponses"] as? JsonArray
        ?: invalidGateContractResponse("JMAP response did not contain methodResponses")
    if (methodResponses.size != 1) {
        invalidGateContractResponse("JMAP response did not contain exactly one result")
    }
    val tuple = methodResponses.single() as? JsonArray
        ?: invalidGateContractResponse("JMAP method result was malformed")
    if (tuple.size != 3) {
        invalidGateContractResponse("JMAP method response tuple was malformed")
    }
    val method = tuple[0].requiredGateString()
    val payload = tuple[1] as? JsonObject
        ?: invalidGateContractResponse("JMAP response arguments were malformed")
    val callId = tuple[2].requiredGateString()
    if (!callId.isSafeGateOpaqueText()) {
        invalidGateContractResponse("JMAP response call ID was malformed")
    }
    return SingleJmapMethodTuple(method = method, payload = payload)
}

private fun JsonObject.requiredGateString(property: String): String =
    this[property]?.requiredGateString()
        ?.takeIf(String::isSafeGateOpaqueText)
        ?: invalidGateContractResponse("JMAP response string was malformed")

private fun JsonElement.requiredGateString(): String =
    (this as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?: invalidGateContractResponse("JMAP response string was malformed")

private fun JsonObject.optionalGateObject(property: String): JsonObject =
    when (val value = this[property]) {
        null, JsonNull -> JsonObject(emptyMap())
        is JsonObject -> value
        else -> invalidGateContractResponse("JMAP response object was malformed")
    }

private fun JsonObject.requiredLedgerString(property: String): String =
    (this[property] as? JsonPrimitive)
        ?.takeIf(JsonPrimitive::isString)
        ?.content
        ?.takeIf(String::isSafeGateOpaqueText)
        ?: throw IllegalStateException("Owned artifact projection was malformed")

private fun String.isSafeGateOpaqueText(): Boolean =
    isBoundedGateRegistryOpaqueText() && '\u0000' !in this

private fun String.isSafeGatePatchPath(): Boolean =
    isSafeGateOpaqueText() && !startsWith('/') && !endsWith('/')

private fun String.isSafeGateMarkerText(): Boolean =
    length in 1..MAXIMUM_GATE_MARKER_CHARS && isSafeGateOpaqueText()

private fun invalidGateContractResponse(message: String): Nothing {
    throw GateJmapException(
        kind = GateJmapFailure.InvalidResponse,
        message = message,
    )
}

private const val MAXIMUM_GATE_SET_UPDATES = 100
private const val MAXIMUM_GATE_MARKER_MAILBOXES = 8
private const val MAXIMUM_GATE_MARKER_CHARS = 512
private const val MAXIMUM_GATE_SMTP_RESPONSE_LINES = 64
private const val MAXIMUM_GATE_SMTP_LINE_CHARS = 2_048
private const val MAXIMUM_GATE_SMTP_MESSAGE_BYTES = 2 * 1_024 * 1_024
private const val GATE_SMTP_HOST = "127.0.0.1"
private const val GATE_SMTP_PORT = 18_587
private const val GATE_SMTP_CONNECT_TIMEOUT_MILLIS = 3_000
private const val GATE_SMTP_READ_TIMEOUT_MILLIS = 5_000
private val SAFE_GATE_LOCAL_PART = Regex("[a-z0-9][a-z0-9-]{0,62}")
private val SAFE_GATE_MESSAGE_ID =
    Regex("[A-Za-z0-9][A-Za-z0-9._+-]{0,190}@local\\.test")
private val SAFE_GATE_ADDRESS =
    Regex("[A-Za-z0-9][A-Za-z0-9._+-]{0,190}@local\\.test")
private val ENHANCED_SMTP_STATUS = Regex("(?:^|\\s)([245]\\.[0-9]{1,3}\\.[0-9]{1,3})(?:\\s|$)")
private val REQUIRED_GATE_MESSAGE_HEADERS = setOf(
    "from",
    "to",
    "date",
    "subject",
    "message-id",
    "mime-version",
    "content-type",
)
