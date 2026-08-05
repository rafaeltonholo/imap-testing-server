package mail.sandbox.dashboard.server.provider.dovecot

import mail.sandbox.dashboard.server.gate.dovecot.EligibilityAddress
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityPaths
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.time.Duration

internal enum class DovecotProtocol {
    Imap,
    Pop3,
}

internal data class DovecotAccount(
    val address: String,
    val protocols: Set<DovecotProtocol>,
)

internal data class DovecotFolder(val name: String)

internal data class DovecotMailboxState(
    val uidValidity: Long,
    val mailboxGuid: String,
) {
    init {
        require(uidValidity > 0) { "Dovecot UIDVALIDITY is invalid" }
        require(MAILBOX_GUID.matches(mailboxGuid)) { "Dovecot mailbox GUID is invalid" }
    }

    fun encode(): String = "$uidValidity:$mailboxGuid"

    companion object {
        private val MAILBOX_GUID = Regex("[0-9a-fA-F]{32}")

        fun decode(value: String): DovecotMailboxState {
            val (uidValidity, mailboxGuid) = value.split(':', limit = 2)
                .takeIf { it.size == 2 }
                ?: throw IllegalArgumentException("Dovecot mutation state is invalid")
            return DovecotMailboxState(
                uidValidity = uidValidity.toLongOrNull()
                    ?: throw IllegalArgumentException("Dovecot mutation state is invalid"),
                mailboxGuid = mailboxGuid,
            )
        }
    }
}

internal data class DovecotMessageSummary(
    val uid: Long,
    val mailboxState: DovecotMailboxState,
    val messageId: String,
    val subject: String,
    val from: String,
    val date: String,
    val flags: Set<String>,
)

internal class DovecotCommandException(message: String) : IllegalStateException(message)

internal class DovecotProductAdapter(
    private val accounts: DovecotAccountRegistry,
    private val runner: DovecotCommandRunner,
) {
    fun listAccounts(): List<DovecotAccount> = accounts.list()
        .sorted()
        .map(::account)

    fun createAccount(address: String, password: ByteArray): DovecotAccount {
        val validatedAddress = requireLocalAddress(address)
        requirePassword(password)
        accounts.create(validatedAddress, password)
        try {
            reloadAuthentication()
            val existing = listFolders(validatedAddress).mapTo(hashSetOf()) { it.name }
            val missing = DEFAULT_MAILBOXES.filterNot(existing::contains)
            if (missing.isNotEmpty()) {
                execute(
                    doveadm(
                        "mailbox",
                        "create",
                        "-u",
                        validatedAddress,
                        *missing.toTypedArray(),
                    ),
                )
            }
        } catch (failure: Exception) {
            runCatching {
                accounts.delete(validatedAddress)
                reloadAuthentication()
            }
            throw failure
        }
        return account(validatedAddress)
    }

    fun changePassword(address: String, password: ByteArray) {
        val validatedAddress = requireLocalAddress(address)
        requirePassword(password)
        accounts.changePassword(validatedAddress, password)
        reloadAuthentication()
    }

    fun deleteAccount(address: String) {
        accounts.delete(requireLocalAddress(address))
        reloadAuthentication()
    }

    fun logs(lines: Int = 200): List<String> {
        require(lines in 1..MAXIMUM_LOG_LINES) { "Log line count is invalid" }
        return execute(
            listOf(
                "docker", "compose", "logs", "--no-color", "--tail", lines.toString(),
                "dovecot",
            ),
            maximumOutputBytes = LOG_OUTPUT_BYTES,
        ).decodeUtf8().lineSequence().filter(String::isNotEmpty).toList()
    }

    fun logsForAccount(address: String, lines: Int = 200): List<String> {
        val validatedAddress = requireLocalAddress(address)
        return logs(lines).filter { line -> validatedAddress in line }
    }

    fun listFolders(address: String): List<DovecotFolder> = execute(
        doveadm("mailbox", "list", "-u", requireLocalAddress(address)),
    ).decodeUtf8()
        .lineSequence()
        .map { it.removeSuffix("\r") }
        .filter(String::isNotEmpty)
        .map(::requireMailbox)
        .distinct()
        .sorted()
        .map(::DovecotFolder)
        .toList()

    fun createFolder(address: String, mailbox: String) {
        val validatedMailbox = requireMutableMailbox(mailbox)
        execute(
            doveadm(
                "mailbox", "create", "-u", requireLocalAddress(address), validatedMailbox,
            ),
        )
    }

    fun deleteFolder(address: String, mailbox: String) {
        val validatedMailbox = requireMutableMailbox(mailbox)
        execute(
            doveadm(
                "mailbox", "delete", "-s", "-u", requireLocalAddress(address),
                validatedMailbox,
            ),
        )
    }

    fun saveRawEmail(address: String, mailbox: String, eml: ByteArray) {
        requireValidEml(eml)
        execute(
            doveadm(
                "save", "-u", requireLocalAddress(address), "-m", requireMailbox(mailbox),
            ),
            stdin = eml,
            maximumOutputBytes = COMMAND_OUTPUT_BYTES,
        )
    }

    fun listMessages(address: String, mailbox: String): List<DovecotMessageSummary> {
        val validatedAddress = requireLocalAddress(address)
        val validatedMailbox = requireMailbox(mailbox)
        val mailboxState = mailboxState(validatedAddress, validatedMailbox)
        val output = execute(
            doveadm(
                "-f", "pager", "fetch", "-u", validatedAddress,
                SUMMARY_FIELDS, "mailbox-guid", mailboxState.mailboxGuid, "all",
            ),
            maximumOutputBytes = MESSAGE_LIST_OUTPUT_BYTES,
        ).decodeUtf8()
        if (output.isBlank()) return emptyList()
        return output.split(PAGER_RECORD_SEPARATOR)
            .map(String::trimRecordBoundary)
            .filter(String::isNotEmpty)
            .map { record -> parseSummaryRecord(record, mailboxState) }
    }

    fun readRawMessage(
        address: String,
        mailbox: String,
        uid: Long,
        expectedState: DovecotMailboxState,
    ): String {
        val validatedAddress = requireLocalAddress(address)
        requireCurrentState(validatedAddress, requireMailbox(mailbox), expectedState)
        val output = execute(
            doveadm(
                "-f", "pager", "fetch", "-u", validatedAddress, "text",
                "mailbox-guid", expectedState.mailboxGuid, "uid", requireUid(uid),
            ),
            maximumOutputBytes = RAW_MESSAGE_OUTPUT_BYTES,
        ).decodeUtf8()
        val rawMessage = when {
            output.startsWith("text: ") -> output.removePrefix("text: ")
            output.startsWith("text:\r\n") -> output.removePrefix("text:\r\n")
            output.startsWith("text:\n") -> output.removePrefix("text:\n")
            else -> throw DovecotCommandException("Dovecot returned an invalid message")
        }.removeSuffix("\u000c")
        requireCurrentState(validatedAddress, mailbox, expectedState)
        return rawMessage
    }

    fun markRead(
        address: String,
        mailbox: String,
        uids: List<Long>,
        expectedState: DovecotMailboxState,
        read: Boolean,
    ) {
        setMessageFlag(address, mailbox, uids, expectedState, "\\Seen", read)
    }

    fun setFlagged(
        address: String,
        mailbox: String,
        uids: List<Long>,
        expectedState: DovecotMailboxState,
        flagged: Boolean,
    ) {
        setMessageFlag(address, mailbox, uids, expectedState, "\\Flagged", flagged)
    }

    fun copyMessages(
        address: String,
        mailbox: String,
        uids: List<Long>,
        expectedState: DovecotMailboxState,
        destination: String,
    ) {
        relocate("copy", address, mailbox, uids, expectedState, destination)
    }

    fun moveMessages(
        address: String,
        mailbox: String,
        uids: List<Long>,
        expectedState: DovecotMailboxState,
        destination: String,
    ) {
        relocate("move", address, mailbox, uids, expectedState, destination)
    }

    fun trashMessages(
        address: String,
        mailbox: String,
        uids: List<Long>,
        expectedState: DovecotMailboxState,
    ) {
        moveMessages(address, mailbox, uids, expectedState, TRASH_MAILBOX)
    }

    fun deleteMessages(
        address: String,
        mailbox: String,
        uids: List<Long>,
        expectedState: DovecotMailboxState,
    ) {
        val validatedAddress = requireLocalAddress(address)
        requireCurrentState(validatedAddress, requireMailbox(mailbox), expectedState)
        execute(
            doveadm(
                "expunge", "-u", validatedAddress, "mailbox-guid",
                expectedState.mailboxGuid, "uid", requireUids(uids),
            ),
        )
    }

    private fun setMessageFlag(
        address: String,
        mailbox: String,
        uids: List<Long>,
        expectedState: DovecotMailboxState,
        flag: String,
        enabled: Boolean,
    ) {
        val validatedAddress = requireLocalAddress(address)
        requireCurrentState(validatedAddress, requireMailbox(mailbox), expectedState)
        execute(
            doveadm(
                "flags", if (enabled) "add" else "remove", "-u",
                validatedAddress, flag, "mailbox-guid", expectedState.mailboxGuid,
                "uid", requireUids(uids),
            ),
        )
    }

    private fun relocate(
        operation: String,
        address: String,
        mailbox: String,
        uids: List<Long>,
        expectedState: DovecotMailboxState,
        destination: String,
    ) {
        val validatedAddress = requireLocalAddress(address)
        requireCurrentState(validatedAddress, requireMailbox(mailbox), expectedState)
        execute(
            doveadm(
                operation, "-u", validatedAddress, requireMailbox(destination),
                "mailbox-guid", expectedState.mailboxGuid, "uid", requireUids(uids),
            ),
        )
    }

    private fun requireCurrentState(
        address: String,
        mailbox: String,
        expectedState: DovecotMailboxState,
    ) {
        if (mailboxState(address, mailbox) != expectedState) {
            throw DovecotCommandException(
                "Dovecot mailbox changed; refresh messages before retrying",
            )
        }
    }

    private fun mailboxState(address: String, mailbox: String): DovecotMailboxState {
        val output = execute(
            doveadm(
                "-f", "pager", "mailbox", "status", "-u", address,
                "guid uidvalidity", mailbox,
            ),
        ).decodeUtf8()
        val fields = output.substringBefore(PAGER_RECORD_SEPARATOR)
            .lineSequence()
            .map { line -> line.removeSuffix("\r") }
            .mapNotNull { line ->
                val delimiter = line.indexOf(':')
                if (delimiter <= 0) null else {
                    line.substring(0, delimiter) to line.substring(delimiter + 1).trim()
                }
            }
            .toMap()
        val uidValidity = fields["uidvalidity"]?.toLongOrNull()
            ?: throw DovecotCommandException("Dovecot returned an invalid UIDVALIDITY")
        val mailboxGuid = fields["guid"]
            ?: throw DovecotCommandException("Dovecot returned an invalid mailbox GUID")
        return runCatching { DovecotMailboxState(uidValidity, mailboxGuid) }
            .getOrElse { throw DovecotCommandException(it.message ?: "Invalid mailbox state") }
    }

    private fun execute(
        argv: List<String>,
        stdin: ByteArray = ByteArray(0),
        maximumOutputBytes: Int = COMMAND_OUTPUT_BYTES,
    ): ByteArray {
        val result = runner.run(
            DovecotCommandRequest(
                argv = argv,
                stdin = stdin,
                timeout = COMMAND_TIMEOUT,
                maximumOutputBytes = maximumOutputBytes,
            ),
        )
        if (
            result.timedOut ||
            result.exitCode != 0 ||
            result.stdout.size > maximumOutputBytes ||
            result.stderr.size > maximumOutputBytes
        ) {
            val detail = if (result.timedOut) {
                "timed out"
            } else {
                result.stderr.decodeUtf8().trim().take(MAXIMUM_ERROR_CHARACTERS)
                    .ifEmpty { "exit ${result.exitCode}" }
            }
            throw DovecotCommandException("Dovecot command failed: $detail")
        }
        return result.stdout
    }

    private fun parseSummaryRecord(
        record: String,
        mailboxState: DovecotMailboxState,
    ): DovecotMessageSummary {
        val fields = linkedMapOf<String, String>()
        var currentKey: String? = null
        record.lineSequence().forEach { sourceLine ->
            val line = sourceLine.removeSuffix("\r")
            val key = SUMMARY_KEYS.firstOrNull { candidate ->
                line == "$candidate:" || line.startsWith("$candidate: ")
            }
            if (key != null) {
                currentKey = key
                fields[key] = line.removePrefix("$key:").removePrefix(" ")
            } else {
                val continuationKey = requireNotNull(currentKey) {
                    "Dovecot returned an invalid message list"
                }
                fields[continuationKey] = fields.getValue(continuationKey) + "\n" + line
            }
        }
        require(fields.keys == SUMMARY_KEYS) { "Dovecot returned an invalid message list" }
        val uid = fields.getValue("uid").toLongOrNull()
        require(uid != null && uid > 0) { "Dovecot returned an invalid message UID" }
        val flags = fields.getValue("flags")
            .split(' ')
            .filter(String::isNotEmpty)
            .toSortedSet()
        return DovecotMessageSummary(
            uid = uid,
            mailboxState = mailboxState,
            messageId = fields.getValue("hdr.message-id"),
            subject = fields.getValue("hdr.subject"),
            from = fields.getValue("hdr.from"),
            date = fields.getValue("hdr.date"),
            flags = flags,
        )
    }

    private fun requireValidEml(eml: ByteArray) {
        require(eml.isNotEmpty() && eml.size <= MAXIMUM_EML_BYTES && 0.toByte() !in eml) {
            "EML content is invalid"
        }
        val text = eml.decodeUtf8()
        val normalized = text.replace("\r\n", "\n")
        val separator = normalized.indexOf("\n\n")
        require(separator > 0) { "EML headers are invalid" }
        val headers = linkedMapOf<String, MutableList<String>>()
        var currentName: String? = null
        normalized.substring(0, separator).lineSequence().forEach { line ->
            if (line.startsWith(' ') || line.startsWith('\t')) {
                val name = requireNotNull(currentName) { "EML headers are invalid" }
                val values = headers.getValue(name)
                values[values.lastIndex] = values.last() + " " + line.trim()
            } else {
                val delimiter = line.indexOf(':')
                require(delimiter > 0) { "EML headers are invalid" }
                val name = line.substring(0, delimiter).lowercase()
                val value = line.substring(delimiter + 1).trim()
                require(value.isNotEmpty()) { "EML headers are invalid" }
                headers.getOrPut(name, ::mutableListOf).add(value)
                currentName = name
            }
        }
        REQUIRED_EML_HEADERS.forEach { name ->
            require(headers[name]?.any(String::isNotEmpty) == true) { "EML is missing $name" }
        }
    }

    private fun requireLocalAddress(address: String): String {
        val canonical = EligibilityAddress.requireCanonical(address)
        require(canonical.substringAfter('@') == LOCAL_DOMAIN) {
            "Dovecot account must use local.test"
        }
        return canonical
    }

    private fun requirePassword(password: ByteArray) {
        require(
            password.size in 1..MAXIMUM_PASSWORD_BYTES &&
                password.none { it == 0.toByte() || it == '\r'.code.toByte() || it == '\n'.code.toByte() },
        ) {
            "Dovecot password is invalid"
        }
    }

    private fun requireMailbox(mailbox: String): String {
        require(
            mailbox.length in 1..MAXIMUM_MAILBOX_LENGTH &&
                (mailbox == "INBOX" || mailbox.startsWith("INBOX.")) &&
                mailbox == mailbox.trim() &&
                mailbox.none(Char::isISOControl),
        ) {
            "Dovecot mailbox is invalid"
        }
        val segments = mailbox.split('.')
        require(
            segments.first() == "INBOX" &&
                segments.drop(1).all { segment ->
                    segment.isNotEmpty() &&
                        segment.length <= MAXIMUM_MAILBOX_SEGMENT_LENGTH &&
                        segment.all { it.isLetterOrDigit() || it == ' ' || it == '-' || it == '_' }
                },
        ) {
            "Dovecot mailbox is invalid"
        }
        return mailbox
    }

    private fun requireMutableMailbox(mailbox: String): String = requireMailbox(mailbox).also {
        require(it != "INBOX") { "INBOX cannot be created or deleted" }
    }

    private fun requireUid(uid: Long): String {
        require(uid > 0) { "Dovecot UID is invalid" }
        return uid.toString()
    }

    private fun requireUids(uids: List<Long>): String {
        require(uids.isNotEmpty() && uids.distinct().size == uids.size) {
            "Dovecot message IDs are invalid"
        }
        return uids.joinToString(",", transform = ::requireUid)
    }

    private fun doveadm(vararg arguments: String): List<String> = DOVEADM_PREFIX + arguments

    private fun reloadAuthentication() {
        execute(doveadm("reload"))
    }

    private fun account(address: String): DovecotAccount =
        DovecotAccount(address, setOf(DovecotProtocol.Imap, DovecotProtocol.Pop3))

    companion object {
        fun production(): DovecotProductAdapter {
            val paths = EligibilityPaths.production()
            return using(paths)
        }

        fun dashboard(): DovecotProductAdapter {
            val paths = EligibilityPaths.dashboardProvider()
            return using(paths)
        }

        private fun using(paths: EligibilityPaths): DovecotProductAdapter {
            return DovecotProductAdapter(
                accounts = EligibilityDovecotAccountRegistry.production(paths),
                runner = JvmDovecotCommandRunner(paths.repositoryRoot),
            )
        }

        private val DOVEADM_PREFIX = listOf(
            "docker", "compose", "exec", "-T", "dovecot", "doveadm",
        )
        private val COMMAND_TIMEOUT: Duration = Duration.ofSeconds(30)
        private val SUMMARY_KEYS = linkedSetOf(
            "uid", "flags", "hdr.message-id", "hdr.subject", "hdr.from", "hdr.date",
        )
        private const val SUMMARY_FIELDS =
            "uid flags hdr.message-id hdr.subject hdr.from hdr.date"
        private const val PAGER_RECORD_SEPARATOR = '\u000c'
        private const val LOCAL_DOMAIN = "local.test"
        private const val TRASH_MAILBOX = "INBOX.Trash"
        private val DEFAULT_MAILBOXES = listOf(
            "INBOX",
            "INBOX.Sent",
            "INBOX.Drafts",
            TRASH_MAILBOX,
        )
        private const val MAXIMUM_LOG_LINES = 2_000
        private const val MAXIMUM_MAILBOX_LENGTH = 255
        private const val MAXIMUM_MAILBOX_SEGMENT_LENGTH = 64
        private const val MAXIMUM_PASSWORD_BYTES = 4 * 1024
        private const val MAXIMUM_EML_BYTES = 5 * 1024 * 1024
        private const val COMMAND_OUTPUT_BYTES = 256 * 1024
        private const val LOG_OUTPUT_BYTES = 2 * 1024 * 1024
        private const val MESSAGE_LIST_OUTPUT_BYTES = 4 * 1024 * 1024
        private const val RAW_MESSAGE_OUTPUT_BYTES = 8 * 1024 * 1024
        private const val MAXIMUM_ERROR_CHARACTERS = 512
        private val REQUIRED_EML_HEADERS = setOf(
            "from", "to", "date", "subject", "message-id",
        )
    }
}

private fun ByteArray.decodeUtf8(): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT)
    .onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(java.nio.ByteBuffer.wrap(this))
    .toString()

private fun String.trimRecordBoundary(): String = trim('\r', '\n')
