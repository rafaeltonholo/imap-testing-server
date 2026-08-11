package mail.sandbox.dashboard.server.provider.dovecot

import jakarta.mail.Flags
import jakarta.mail.FetchProfile
import jakarta.mail.Folder
import jakarta.mail.Message
import jakarta.mail.Session
import jakarta.mail.UIDFolder
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.Properties
import mail.sandbox.dashboard.server.provider.AccountCredentials
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationMechanism
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProbe
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProtocol
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationRequest
import org.eclipse.angus.mail.imap.IMAPFolder
import org.eclipse.angus.mail.imap.IMAPStore

internal interface DovecotMailboxClient {
    fun probe(credentials: AccountCredentials): AuthenticationOutcome

    fun listFolders(credentials: AccountCredentials): List<DovecotFolder>

    fun createFolder(credentials: AccountCredentials, name: String): DovecotFolder

    fun deleteFolder(credentials: AccountCredentials, id: String)

    fun listMessages(
        credentials: AccountCredentials,
        folder: String,
    ): List<DovecotMessageSummary>

    fun readMessage(
        credentials: AccountCredentials,
        folder: String,
        uid: Long,
    ): String

    fun mutate(credentials: AccountCredentials, command: DovecotMessageCommand)
}

internal sealed interface DovecotMessageCommand {
    val folder: String
    val uids: List<Long>
    val expectedState: DovecotMailboxState

    data class MarkRead(
        override val folder: String,
        override val uids: List<Long>,
        override val expectedState: DovecotMailboxState,
        val read: Boolean,
    ) : DovecotMessageCommand

    data class SetFlagged(
        override val folder: String,
        override val uids: List<Long>,
        override val expectedState: DovecotMailboxState,
        val flagged: Boolean,
    ) : DovecotMessageCommand

    data class Copy(
        override val folder: String,
        override val uids: List<Long>,
        override val expectedState: DovecotMailboxState,
        val destination: String,
    ) : DovecotMessageCommand

    data class Move(
        override val folder: String,
        override val uids: List<Long>,
        override val expectedState: DovecotMailboxState,
        val destination: String,
    ) : DovecotMessageCommand

    data class Trash(
        override val folder: String,
        override val uids: List<Long>,
        override val expectedState: DovecotMailboxState,
    ) : DovecotMessageCommand

    data class Delete(
        override val folder: String,
        override val uids: List<Long>,
        override val expectedState: DovecotMailboxState,
    ) : DovecotMessageCommand
}

internal class DovecotMailboxChangedException : IllegalStateException(
    "Dovecot mailbox changed; refresh messages before retrying",
)

internal class DovecotMessageMissingException(uid: Long) : IllegalStateException(
    "Dovecot message UID $uid was not found; refresh messages before retrying",
)

internal data class DovecotImapConnectionSettings(
    val host: String = "127.0.0.1",
    val port: Int = 1143,
    val timeoutMillis: Int = 10_000,
) {
    init {
        require(host.isNotBlank())
        require(port in 1..65_535)
        require(timeoutMillis in 1..30_000)
    }

    fun sessionProperties(): Properties = Properties().apply {
        setProperty("mail.imap.host", host)
        setProperty("mail.imap.port", port.toString())
        setProperty("mail.imap.connectiontimeout", timeoutMillis.toString())
        setProperty("mail.imap.timeout", timeoutMillis.toString())
        setProperty("mail.imap.writetimeout", timeoutMillis.toString())
        setProperty("mail.imap.starttls.enable", "true")
        setProperty("mail.imap.starttls.required", "true")
        setProperty("mail.imap.ssl.trust", host)
        setProperty("mail.imap.auth", "true")
        setProperty("mail.imap.peek", "true")
    }
}

internal fun interface DovecotImapStoreFactory {
    fun create(): DovecotImapStore
}

internal interface DovecotImapStore : AutoCloseable {
    fun connect(credentials: AccountCredentials)

    fun listFolders(maximumFolders: Int): List<DovecotFolder>

    fun createFolder(name: String): DovecotFolder

    fun deleteFolder(name: String)

    fun openFolder(name: String, writable: Boolean): DovecotImapFolder
}

internal interface DovecotImapFolder {
    val uidValidity: Long

    val supportsTargetedExpunge: Boolean
        get() = true

    fun listMessages(maximumMessages: Int): List<DovecotStoredMessage>

    fun readMessage(uid: Long, maximumBytes: Int): String

    fun contains(uid: Long): Boolean

    fun setFlag(uids: List<Long>, flag: String, enabled: Boolean)

    fun copy(uids: List<Long>, destination: String)

    /** Returns true only when a native IMAP MOVE was issued. */
    fun move(uids: List<Long>, destination: String): Boolean

    fun targetedDeleteAndExpunge(uids: List<Long>)

    fun close(expunge: Boolean)
}

internal data class DovecotStoredMessage(
    val uid: Long,
    val messageId: String,
    val subject: String,
    val from: String,
    val date: String,
    val flags: Set<String>,
)

internal class DovecotImapClient(
    private val storeFactory: DovecotImapStoreFactory = JakartaDovecotImapStoreFactory(),
    private val authenticationProbe: (AccountCredentials) -> AuthenticationOutcome =
        DefaultDovecotImapAuthenticationProbe()::probe,
) : DovecotMailboxClient {
    override fun probe(credentials: AccountCredentials): AuthenticationOutcome =
        authenticationProbe(credentials)

    override fun listFolders(credentials: AccountCredentials): List<DovecotFolder> =
        withStore(credentials) { store ->
            store.listFolders(MAXIMUM_FOLDERS)
                .distinctBy(DovecotFolder::name)
                .sortedBy(DovecotFolder::name)
                .take(MAXIMUM_FOLDERS)
        }

    override fun createFolder(
        credentials: AccountCredentials,
        name: String,
    ): DovecotFolder = withStore(credentials) { store ->
        store.createFolder(requireMutableMailbox(name))
    }

    override fun deleteFolder(credentials: AccountCredentials, id: String) {
        withStore(credentials) { store ->
            store.deleteFolder(requireMutableMailbox(id))
        }
    }

    override fun listMessages(
        credentials: AccountCredentials,
        folder: String,
    ): List<DovecotMessageSummary> = withFolder(
        credentials = credentials,
        mailbox = requireMailbox(folder),
        writable = false,
    ) { selected ->
        val state = DovecotMailboxState(uidValidity = selected.uidValidity)
        selected.listMessages(MAXIMUM_MESSAGES).map { message ->
            require(message.uid > 0) { "Dovecot returned an invalid message UID" }
            DovecotMessageSummary(
                uid = message.uid,
                mailboxState = state,
                messageId = message.messageId,
                subject = message.subject,
                from = message.from,
                date = message.date,
                flags = message.flags,
            )
        }
    }

    override fun readMessage(
        credentials: AccountCredentials,
        folder: String,
        uid: Long,
    ): String = withFolder(
        credentials = credentials,
        mailbox = requireMailbox(folder),
        writable = false,
    ) { selected ->
        val validatedUid = requireUid(uid)
        if (!selected.contains(validatedUid)) throw DovecotMessageMissingException(validatedUid)
        selected.readMessage(validatedUid, MAXIMUM_RAW_MESSAGE_BYTES)
    }

    override fun mutate(credentials: AccountCredentials, command: DovecotMessageCommand) {
        val mailbox = requireMailbox(command.folder)
        val uids = requireUids(command.uids)
        withFolder(credentials, mailbox, writable = true) { selected ->
            if (selected.uidValidity != command.expectedState.uidValidity) {
                throw DovecotMailboxChangedException()
            }
            uids.firstOrNull { uid -> !selected.contains(uid) }
                ?.let { uid -> throw DovecotMessageMissingException(uid) }
            when (command) {
                is DovecotMessageCommand.MarkRead ->
                    selected.setFlag(uids, "\\Seen", command.read)
                is DovecotMessageCommand.SetFlagged ->
                    selected.setFlag(uids, "\\Flagged", command.flagged)
                is DovecotMessageCommand.Copy ->
                    selected.copy(uids, requireMailbox(command.destination))
                is DovecotMessageCommand.Move ->
                    move(selected, uids, requireMailbox(command.destination))
                is DovecotMessageCommand.Trash ->
                    move(selected, uids, TRASH_MAILBOX)
                is DovecotMessageCommand.Delete ->
                    selected.targetedDeleteAndExpunge(uids)
            }
        }
    }

    private fun move(folder: DovecotImapFolder, uids: List<Long>, destination: String) {
        if (folder.move(uids, destination)) return
        check(folder.supportsTargetedExpunge) {
            "Dovecot requires UIDPLUS for targeted MOVE fallback"
        }
        folder.copy(uids, destination)
        folder.targetedDeleteAndExpunge(uids)
    }

    private inline fun <T> withStore(
        credentials: AccountCredentials,
        block: (DovecotImapStore) -> T,
    ): T {
        requireCredentials(credentials)
        val store = storeFactory.create()
        return try {
            store.connect(credentials)
            block(store)
        } finally {
            runCatching { store.close() }
        }
    }

    private inline fun <T> withFolder(
        credentials: AccountCredentials,
        mailbox: String,
        writable: Boolean,
        block: (DovecotImapFolder) -> T,
    ): T = withStore(credentials) { store ->
        var folder: DovecotImapFolder? = null
        try {
            folder = store.openFolder(mailbox, writable)
            block(folder)
        } finally {
            runCatching { folder?.close(expunge = false) }
        }
    }

    private fun requireCredentials(credentials: AccountCredentials) {
        require(credentials.address.isNotBlank()) { "Dovecot account is required" }
        require(!credentials.password.isNullOrEmpty()) {
            "Dovecot account password is required"
        }
    }

    private fun requireMailbox(mailbox: String): String {
        require(
            mailbox.length in 1..MAXIMUM_MAILBOX_LENGTH &&
                (mailbox == "INBOX" || mailbox.startsWith("INBOX.")) &&
                mailbox == mailbox.trim() &&
                mailbox.none(Char::isISOControl),
        ) { "Dovecot mailbox is invalid" }
        val segments = mailbox.split('.')
        require(
            segments.first() == "INBOX" &&
                segments.drop(1).all { segment ->
                    segment.isNotEmpty() &&
                        segment.length <= MAXIMUM_MAILBOX_SEGMENT_LENGTH &&
                        segment.all { character ->
                            character.isLetterOrDigit() || character in " -_"
                        }
                },
        ) { "Dovecot mailbox is invalid" }
        return mailbox
    }

    private fun requireMutableMailbox(mailbox: String): String = requireMailbox(mailbox).also {
        require(it != "INBOX") { "INBOX cannot be created or deleted" }
    }

    private fun requireUid(uid: Long): Long = uid.also {
        require(it in 1..UIDFolder.MAXUID) { "Dovecot UID is invalid" }
    }

    private fun requireUids(uids: List<Long>): List<Long> = uids.also {
        require(
            it.isNotEmpty() &&
                it.size <= MAXIMUM_MUTATION_UIDS &&
                it.distinct().size == it.size &&
                it.all { uid -> uid in 1..UIDFolder.MAXUID },
        ) { "Dovecot message IDs are invalid" }
    }

    private companion object {
        const val MAXIMUM_FOLDERS = 1_000
        const val MAXIMUM_MESSAGES = 1_000
        const val MAXIMUM_MUTATION_UIDS = 500
        const val MAXIMUM_RAW_MESSAGE_BYTES = 8 * 1024 * 1024
        const val MAXIMUM_MAILBOX_LENGTH = 255
        const val MAXIMUM_MAILBOX_SEGMENT_LENGTH = 64
        const val TRASH_MAILBOX = "INBOX.Trash"
    }
}

private class DefaultDovecotImapAuthenticationProbe(
    private val probe: ProviderAuthenticationProbe = ProviderAuthenticationProbe(),
) {
    fun probe(credentials: AccountCredentials): AuthenticationOutcome = probe.probe(
        ProviderAuthenticationRequest(
            protocol = ProviderAuthenticationProtocol.IMAP,
            mechanism = ProviderAuthenticationMechanism.PASSWORD,
            credentials = credentials,
        ),
    )
}

private class JakartaDovecotImapStoreFactory(
    private val settings: DovecotImapConnectionSettings = DovecotImapConnectionSettings(),
) : DovecotImapStoreFactory {
    override fun create(): DovecotImapStore {
        val session = Session.getInstance(settings.sessionProperties())
        return JakartaDovecotImapStore(
            store = session.getStore("imap") as IMAPStore,
            settings = settings,
        )
    }
}

private class JakartaDovecotImapStore(
    private val store: IMAPStore,
    private val settings: DovecotImapConnectionSettings,
) : DovecotImapStore {
    override fun connect(credentials: AccountCredentials) {
        store.connect(
            settings.host,
            settings.port,
            credentials.address,
            requireNotNull(credentials.password),
        )
    }

    override fun listFolders(maximumFolders: Int): List<DovecotFolder> =
        store.defaultFolder.list("*")
            .asSequence()
            .take(maximumFolders)
            .map { folder -> DovecotFolder(folder.fullName) }
            .toList()

    override fun createFolder(name: String): DovecotFolder {
        val folder = store.getFolder(name)
        check(folder.create(Folder.HOLDS_MESSAGES)) { "Dovecot did not create mailbox $name" }
        runCatching { folder.isSubscribed = true }
        return DovecotFolder(folder.fullName)
    }

    override fun deleteFolder(name: String) {
        check(store.getFolder(name).delete(false)) { "Dovecot did not delete mailbox $name" }
    }

    override fun openFolder(name: String, writable: Boolean): DovecotImapFolder {
        val folder = store.getFolder(name) as IMAPFolder
        return try {
            folder.open(if (writable) Folder.READ_WRITE else Folder.READ_ONLY)
            JakartaDovecotImapFolder(store, folder)
        } catch (failure: Exception) {
            if (folder.isOpen) runCatching { folder.close(false) }
            throw failure
        }
    }

    override fun close() {
        if (store.isConnected) store.close()
    }
}

private class JakartaDovecotImapFolder(
    private val store: IMAPStore,
    private val folder: IMAPFolder,
) : DovecotImapFolder {
    override val uidValidity: Long
        get() = folder.uidValidity

    override val supportsTargetedExpunge: Boolean
        get() = store.hasCapability("UIDPLUS")

    override fun listMessages(maximumMessages: Int): List<DovecotStoredMessage> {
        val messageCount = folder.messageCount
        if (messageCount <= 0) return emptyList()
        val first = maxOf(1, messageCount - maximumMessages + 1)
        val messages = folder.getMessages(first, messageCount)
        folder.fetch(
            messages,
            FetchProfile().apply {
                add(FetchProfile.Item.ENVELOPE)
                add(FetchProfile.Item.FLAGS)
                add(FetchProfile.Item.SIZE)
                add(UIDFolder.FetchProfileItem.UID)
            },
        )
        return messages.map(::storedMessage)
    }

    override fun readMessage(uid: Long, maximumBytes: Int): String {
        val message = requireMessage(uid)
        val bytes = ByteArrayOutputStream(minOf(maximumBytes, 64 * 1024))
        message.writeTo(BoundedOutputStream(bytes, maximumBytes))
        return bytes.toString(StandardCharsets.UTF_8)
    }

    override fun contains(uid: Long): Boolean = folder.getMessageByUID(uid) != null

    override fun setFlag(uids: List<Long>, flag: String, enabled: Boolean) {
        val systemFlag = when (flag) {
            "\\Seen" -> Flags.Flag.SEEN
            "\\Flagged" -> Flags.Flag.FLAGGED
            else -> throw IllegalArgumentException("Unsupported Dovecot system flag")
        }
        folder.setFlags(messages(uids), Flags(systemFlag), enabled)
    }

    override fun copy(uids: List<Long>, destination: String) {
        folder.copyMessages(messages(uids), store.getFolder(destination))
    }

    override fun move(uids: List<Long>, destination: String): Boolean {
        if (!store.hasCapability("MOVE")) return false
        folder.moveMessages(messages(uids), store.getFolder(destination))
        return true
    }

    override fun targetedDeleteAndExpunge(uids: List<Long>) {
        check(supportsTargetedExpunge) {
            "Dovecot requires UIDPLUS for targeted expunge"
        }
        val messages = messages(uids)
        folder.setFlags(messages, Flags(Flags.Flag.DELETED), true)
        folder.expunge(messages)
    }

    override fun close(expunge: Boolean) {
        require(!expunge) { "Dashboard IMAP folders must never broadly expunge on close" }
        if (folder.isOpen) folder.close(false)
    }

    private fun messages(uids: List<Long>): Array<Message> {
        val resolved = folder.getMessagesByUID(uids.toLongArray())
        return Array(resolved.size) { index ->
            resolved[index] ?: throw DovecotMessageMissingException(uids[index])
        }
    }

    private fun requireMessage(uid: Long): Message = folder.getMessageByUID(uid)
        ?: throw DovecotMessageMissingException(uid)

    private fun storedMessage(message: Message): DovecotStoredMessage {
        val flags = buildSet {
            if (message.isSet(Flags.Flag.ANSWERED)) add("\\Answered")
            if (message.isSet(Flags.Flag.DELETED)) add("\\Deleted")
            if (message.isSet(Flags.Flag.DRAFT)) add("\\Draft")
            if (message.isSet(Flags.Flag.FLAGGED)) add("\\Flagged")
            if (message.isSet(Flags.Flag.RECENT)) add("\\Recent")
            if (message.isSet(Flags.Flag.SEEN)) add("\\Seen")
            addAll(message.flags.userFlags)
        }
        return DovecotStoredMessage(
            uid = folder.getUID(message),
            messageId = message.getHeader("Message-ID")?.firstOrNull().orEmpty(),
            subject = message.subject.orEmpty(),
            from = message.from?.joinToString(", ").orEmpty(),
            date = message.getHeader("Date")?.firstOrNull().orEmpty(),
            flags = flags,
        )
    }
}

private class BoundedOutputStream(
    private val delegate: OutputStream,
    private val maximumBytes: Int,
) : OutputStream() {
    private var written = 0

    override fun write(value: Int) {
        requireCapacity(1)
        delegate.write(value)
        written++
    }

    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        requireCapacity(length)
        delegate.write(bytes, offset, length)
        written += length
    }

    private fun requireCapacity(count: Int) {
        check(count >= 0 && written <= maximumBytes - count) {
            "Dovecot message exceeds the dashboard size limit"
        }
    }
}
