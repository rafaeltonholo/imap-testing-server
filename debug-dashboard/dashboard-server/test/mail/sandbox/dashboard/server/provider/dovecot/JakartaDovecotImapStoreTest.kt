package mail.sandbox.dashboard.server.provider.dovecot

import jakarta.mail.FetchProfile
import jakarta.mail.Flags
import jakarta.mail.Folder
import jakarta.mail.Message
import jakarta.mail.Session
import jakarta.mail.UIDFolder
import jakarta.mail.URLName
import jakarta.mail.internet.MimeMessage
import java.io.ByteArrayInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import mail.sandbox.dashboard.server.provider.AccountCredentials
import org.eclipse.angus.mail.imap.IMAPFolder
import org.eclipse.angus.mail.imap.IMAPStore

class JakartaDovecotImapStoreTest {
    @Test
    fun concreteAngusStoreAuthenticatesTheOrdinaryAccountAndClosesWithoutExpunge() {
        val settings = DovecotImapConnectionSettings()
        val state = RecordingAngusState()
        val store = RecordingAngusStore(
            Session.getInstance(settings.sessionProperties()),
            state,
        )
        val adapter = JakartaDovecotImapStore(store, settings)

        adapter.connect(AccountCredentials("alice@local.test", "alice-password"))
        adapter.openFolder("INBOX", writable = false).close(expunge = false)
        adapter.openFolder("INBOX", writable = true).close(expunge = false)
        adapter.close()

        assertEquals(
            AngusConnectCall("127.0.0.1", 1143, "alice@local.test", "alice-password"),
            state.connectCall,
        )
        assertEquals(listOf(Folder.READ_ONLY, Folder.READ_WRITE), state.openModes)
        assertEquals(listOf(false, false), state.closeExpungeArguments)
        assertEquals(1, state.storeCloseCount)
        assertFalse(state.connected)
        assertTrue("expunge-all" !in state.operations)
    }

    @Test
    fun concreteAngusFolderExecutesUidMoveAndTargetedExpungeOperations() {
        val settings = DovecotImapConnectionSettings()
        val session = Session.getInstance(settings.sessionProperties())
        val unrelatedDeleted = fixtureMessage(session).apply {
            setHeader("Message-ID", "<unrelated-deleted@local.test>")
            setFlag(Flags.Flag.DELETED, true)
        }
        val state = RecordingAngusState(
            capabilities = setOf("MOVE", "UIDPLUS"),
            mailboxes = linkedMapOf(
                "INBOX" to mutableListOf(
                    AngusStoredMessage(7, fixtureMessage(session)),
                    AngusStoredMessage(8, unrelatedDeleted),
                ),
                "INBOX.Archive" to mutableListOf(),
            ),
        )
        val adapter = JakartaDovecotImapStore(RecordingAngusStore(session, state), settings)
        adapter.connect(AccountCredentials("alice@local.test", "alice-password"))

        assertEquals(listOf("INBOX"), adapter.listFolders(1).map(DovecotFolder::name))
        assertEquals(
            setOf("INBOX", "INBOX.Archive"),
            adapter.listFolders(10).map(DovecotFolder::name).toSet(),
        )
        assertEquals(DovecotFolder("INBOX.New"), adapter.createFolder("INBOX.New"))
        adapter.deleteFolder("INBOX.New")

        val folder = adapter.openFolder("INBOX", writable = true)
        val listed = folder.listMessages(10).first { message -> message.uid == 7L }
        assertEquals(7L, listed.uid)
        assertEquals("<fixture@local.test>", listed.messageId)
        assertTrue(folder.readMessage(7, 8_192).contains("fixture body"))
        assertTrue(folder.contains(7))
        folder.setFlag(listOf(7), "\\Seen", enabled = true)
        folder.copy(listOf(7), "INBOX.Archive")
        assertTrue(folder.move(listOf(7), "INBOX.Archive"))
        assertTrue(folder.supportsTargetedExpunge)
        folder.targetedDeleteAndExpunge(listOf(7))
        folder.close(expunge = false)
        adapter.close()

        assertTrue(state.fetchProfiles.single().contains(FetchProfile.Item.ENVELOPE))
        assertTrue(state.fetchProfiles.single().contains(FetchProfile.Item.FLAGS))
        assertTrue(state.fetchProfiles.single().contains(FetchProfile.Item.SIZE))
        assertTrue(state.fetchProfiles.single().contains(UIDFolder.FetchProfileItem.UID))
        assertEquals(listOf("*", "*"), state.listPatterns)
        assertEquals(listOf(Folder.HOLDS_MESSAGES), state.createTypes)
        assertEquals(
            listOf(
                "create:INBOX.New",
                "subscribe:INBOX.New:true",
                "delete:INBOX.New:false",
                "flag:INBOX:\\Seen:true:7",
                "copy:INBOX:INBOX.Archive:7",
                "move:INBOX:INBOX.Archive:7",
                "flag:INBOX:\\Deleted:true:7",
                "targeted-expunge:INBOX:7",
            ),
            state.operations,
        )
        assertTrue("expunge-all" !in state.operations)
        assertEquals(listOf(false), state.closeExpungeArguments)
    }

    @Test
    fun concreteAngusFolderPreservesMissingUidPositionsAndClosesAfterOpenFailure() {
        val settings = DovecotImapConnectionSettings()
        val session = Session.getInstance(settings.sessionProperties())
        val missingUidState = RecordingAngusState(
            capabilities = setOf("UIDPLUS"),
            mailboxes = linkedMapOf(
                "INBOX" to mutableListOf(AngusStoredMessage(7, fixtureMessage(session))),
            ),
        )
        val missingUidAdapter = JakartaDovecotImapStore(
            RecordingAngusStore(session, missingUidState),
            settings,
        )
        missingUidAdapter.connect(AccountCredentials("alice@local.test", "alice-password"))
        val selected = missingUidAdapter.openFolder("INBOX", writable = true)

        assertFailsWith<DovecotMessageMissingException> {
            selected.setFlag(listOf(7, 99), "\\Seen", enabled = true)
        }
        assertTrue(missingUidState.operations.isEmpty())
        selected.close(expunge = false)
        missingUidAdapter.close()

        val failedOpenState = RecordingAngusState(
            openFailureAfterOpening = IllegalStateException("open failed"),
        )
        val failedOpenAdapter = JakartaDovecotImapStore(
            RecordingAngusStore(session, failedOpenState),
            settings,
        )
        failedOpenAdapter.connect(AccountCredentials("alice@local.test", "alice-password"))

        assertFailsWith<IllegalStateException> {
            failedOpenAdapter.openFolder("INBOX", writable = false)
        }
        assertEquals(listOf(false), failedOpenState.closeExpungeArguments)
        failedOpenAdapter.close()
    }

    @Test
    fun concreteAngusFolderRefusesTargetedExpungeWithoutUidPlus() {
        val settings = DovecotImapConnectionSettings()
        val session = Session.getInstance(settings.sessionProperties())
        val state = RecordingAngusState(
            mailboxes = linkedMapOf(
                "INBOX" to mutableListOf(AngusStoredMessage(7, fixtureMessage(session))),
            ),
        )
        val adapter = JakartaDovecotImapStore(RecordingAngusStore(session, state), settings)
        adapter.connect(AccountCredentials("alice@local.test", "alice-password"))
        val folder = adapter.openFolder("INBOX", writable = true)

        assertFalse(folder.move(listOf(7), "INBOX.Archive"))
        assertFalse(folder.supportsTargetedExpunge)
        assertFailsWith<IllegalStateException> {
            folder.targetedDeleteAndExpunge(listOf(7))
        }

        assertTrue(state.operations.isEmpty())
        folder.close(expunge = false)
        adapter.close()
    }

    private fun fixtureMessage(session: Session): Message = MimeMessage(
        session,
        ByteArrayInputStream(
            listOf(
                "From: sender@local.test",
                "To: alice@local.test",
                "Date: Tue, 11 Aug 2026 10:00:00 +0000",
                "Subject: fixture",
                "Message-ID: <fixture@local.test>",
                "",
                "fixture body",
            ).joinToString("\r\n").toByteArray(),
        ),
    )
}

private data class AngusConnectCall(
    val host: String?,
    val port: Int,
    val user: String?,
    val password: String?,
)

private data class AngusStoredMessage(
    val uid: Long,
    val message: Message,
)

private data class RecordingAngusState(
    val capabilities: Set<String> = emptySet(),
    val mailboxes: LinkedHashMap<String, MutableList<AngusStoredMessage>> = linkedMapOf(
        "INBOX" to mutableListOf(),
    ),
    var connected: Boolean = false,
    var connectCall: AngusConnectCall? = null,
    var storeCloseCount: Int = 0,
    val openModes: MutableList<Int> = mutableListOf(),
    val openFailureAfterOpening: RuntimeException? = null,
    val closeExpungeArguments: MutableList<Boolean> = mutableListOf(),
    val listPatterns: MutableList<String> = mutableListOf(),
    val createTypes: MutableList<Int> = mutableListOf(),
    val fetchProfiles: MutableList<FetchProfile> = mutableListOf(),
    val operations: MutableList<String> = mutableListOf(),
)

private class RecordingAngusStore(
    session: Session,
    private val state: RecordingAngusState,
) : IMAPStore(session, URLName("imap", null, -1, null, null, null)) {
    private val folders = linkedMapOf<String, RecordingAngusFolder>()
    private val root = RecordingAngusFolder("", this, state, folders)

    override fun protocolConnect(
        host: String?,
        port: Int,
        user: String?,
        password: String?,
    ): Boolean {
        state.connectCall = AngusConnectCall(host, port, user, password)
        state.connected = true
        return true
    }

    override fun isConnected(): Boolean = state.connected

    override fun getDefaultFolder(): Folder = root

    override fun getFolder(name: String): Folder = folders.getOrPut(name) {
        RecordingAngusFolder(name, this, state, folders)
    }

    override fun getFolder(url: URLName): Folder = getFolder(url.file.orEmpty())

    override fun hasCapability(capability: String): Boolean =
        state.capabilities.any { candidate -> candidate.equals(capability, ignoreCase = true) }

    override fun close() {
        state.storeCloseCount++
        state.connected = false
        setConnected(false)
    }
}

private class RecordingAngusFolder(
    private val mailbox: String,
    private val imapStore: IMAPStore,
    private val state: RecordingAngusState,
    private val folders: MutableMap<String, RecordingAngusFolder>,
) : IMAPFolder(mailbox, '/', imapStore, true) {
    private var open = false

    override fun list(pattern: String): Array<Folder> {
        state.listPatterns += pattern
        return state.mailboxes.keys.map { name ->
            folders.getOrPut(name) {
                RecordingAngusFolder(name, imapStore, state, folders)
            }
        }.toTypedArray()
    }

    override fun create(type: Int): Boolean {
        state.mailboxes.putIfAbsent(mailbox, mutableListOf())
        state.createTypes += type
        state.operations += "create:$mailbox"
        return true
    }

    override fun setSubscribed(subscribe: Boolean) {
        state.operations += "subscribe:$mailbox:$subscribe"
    }

    override fun delete(recurse: Boolean): Boolean {
        state.mailboxes.remove(mailbox)
        state.operations += "delete:$mailbox:$recurse"
        return true
    }

    override fun open(mode: Int) {
        open = true
        state.openModes += mode
        state.openFailureAfterOpening?.let { throw it }
    }

    override fun close(expunge: Boolean) {
        open = false
        state.closeExpungeArguments += expunge
    }

    override fun isOpen(): Boolean = open

    override fun getUIDValidity(): Long = 4_242

    override fun getMessageCount(): Int = messages().size

    override fun getMessage(messageNumber: Int): Message = messages()[messageNumber - 1].message

    override fun getMessages(start: Int, end: Int): Array<Message> = messages()
        .subList(start - 1, end)
        .map(AngusStoredMessage::message)
        .toTypedArray()

    override fun fetch(messages: Array<out Message>, fetchProfile: FetchProfile) {
        state.fetchProfiles += fetchProfile
    }

    override fun getUID(message: Message): Long = stored(message).uid

    override fun getMessageByUID(uid: Long): Message? = messages()
        .firstOrNull { stored -> stored.uid == uid }
        ?.message

    override fun getMessagesByUID(uids: LongArray): Array<Message?> =
        Array(uids.size) { index -> getMessageByUID(uids[index]) }

    override fun setFlags(messages: Array<out Message>, flags: Flags, value: Boolean) {
        val flag = when {
            flags.contains(Flags.Flag.SEEN) -> "\\Seen"
            flags.contains(Flags.Flag.FLAGGED) -> "\\Flagged"
            flags.contains(Flags.Flag.DELETED) -> "\\Deleted"
            else -> flags.toString()
        }
        state.operations += "flag:$mailbox:$flag:$value:${uids(messages)}"
        messages.forEach { message -> message.setFlags(flags, value) }
    }

    override fun copyMessages(messages: Array<out Message>, folder: Folder) {
        state.operations += "copy:$mailbox:${folder.fullName}:${uids(messages)}"
    }

    override fun moveMessages(messages: Array<out Message>, folder: Folder) {
        state.operations += "move:$mailbox:${folder.fullName}:${uids(messages)}"
    }

    override fun expunge(messages: Array<out Message>): Array<Message> {
        state.operations += "targeted-expunge:$mailbox:${uids(messages)}"
        return Array(messages.size) { index -> messages[index] }
    }

    override fun expunge(): Array<Message> {
        state.operations += "expunge-all"
        return emptyArray()
    }

    private fun messages(): MutableList<AngusStoredMessage> =
        state.mailboxes.getOrPut(mailbox) { mutableListOf() }

    private fun stored(message: Message): AngusStoredMessage = messages()
        .first { stored -> stored.message === message }

    private fun uids(messages: Array<out Message>): String =
        messages.joinToString(",") { message -> stored(message).uid.toString() }
}
