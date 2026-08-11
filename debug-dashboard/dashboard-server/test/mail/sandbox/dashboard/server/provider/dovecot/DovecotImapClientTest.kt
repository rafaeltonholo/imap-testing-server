package mail.sandbox.dashboard.server.provider.dovecot

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import mail.sandbox.dashboard.server.provider.AccountCredentials
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome

class DovecotImapClientTest {
    @Test
    fun mailboxWorkUsesTheSelectedOrdinaryAccountAndClosesEveryResource() {
        val state = RecordingMailboxState()
        val factory = RecordingStoreFactory(state)
        val client = DovecotImapClient(
            storeFactory = factory,
            authenticationProbe = { AuthenticationOutcome.Authenticated("IMAP authenticated") },
        )
        val credentials = AccountCredentials(
            address = "alice@local.test",
            password = "alice-password",
        )

        assertEquals(
            AuthenticationOutcome.Authenticated("IMAP authenticated"),
            client.probe(credentials),
        )
        assertEquals(
            listOf(DovecotFolder("INBOX"), DovecotFolder("INBOX.Trash")),
            client.listFolders(credentials),
        )
        assertEquals(
            DovecotFolder("INBOX.Archive"),
            client.createFolder(credentials, "INBOX.Archive"),
        )
        client.deleteFolder(credentials, "INBOX.Archive")
        assertEquals(listOf(7L), client.listMessages(credentials, "INBOX").map { it.uid })
        assertEquals("Subject: fixture\r\n\r\nbody", client.readMessage(credentials, "INBOX", 7))

        assertTrue(factory.credentials.all { it == credentials })
        assertTrue(factory.credentials.none { it.address.startsWith("dashboard-") })
        assertEquals(factory.credentials.size, state.storeCloseCount)
        assertEquals(2, state.folderCloseCount)
        assertEquals(listOf(false, false), state.folderCloseExpungeArguments)
    }

    @Test
    fun mutationsCheckUidValidityAndUseOnlyTargetedUidOperations() {
        val state = RecordingMailboxState(uidValidity = 4_242)
        val client = DovecotImapClient(
            storeFactory = RecordingStoreFactory(state),
            authenticationProbe = { AuthenticationOutcome.Authenticated("ok") },
        )
        val credentials = AccountCredentials("alice@local.test", "alice-password")
        val current = DovecotMailboxState(uidValidity = 4_242)

        assertFailsWith<DovecotMailboxChangedException> {
            client.mutate(
                credentials,
                DovecotMessageCommand.MarkRead(
                    folder = "INBOX",
                    uids = listOf(7),
                    expectedState = DovecotMailboxState(uidValidity = 4_241),
                    read = true,
                ),
            )
        }
        assertTrue(state.operations.isEmpty())

        client.mutate(
            credentials,
            DovecotMessageCommand.MarkRead("INBOX", listOf(7), current, read = true),
        )
        client.mutate(
            credentials,
            DovecotMessageCommand.MarkRead("INBOX", listOf(7), current, read = false),
        )
        client.mutate(
            credentials,
            DovecotMessageCommand.SetFlagged("INBOX", listOf(7), current, flagged = true),
        )
        client.mutate(
            credentials,
            DovecotMessageCommand.SetFlagged("INBOX", listOf(7), current, flagged = false),
        )
        client.mutate(
            credentials,
            DovecotMessageCommand.Copy("INBOX", listOf(7), current, "INBOX.Archive"),
        )
        client.mutate(
            credentials,
            DovecotMessageCommand.Move("INBOX", listOf(7), current, "INBOX.Archive"),
        )
        client.mutate(
            credentials,
            DovecotMessageCommand.Trash("INBOX", listOf(7), current),
        )
        client.mutate(
            credentials,
            DovecotMessageCommand.Delete("INBOX", listOf(7), current),
        )

        assertEquals(
            listOf(
                "flag:\\Seen:true:7",
                "flag:\\Seen:false:7",
                "flag:\\Flagged:true:7",
                "flag:\\Flagged:false:7",
                "copy:INBOX.Archive:7",
                "copy:INBOX.Archive:7",
                "targeted-expunge:7",
                "copy:INBOX.Trash:7",
                "targeted-expunge:7",
                "targeted-expunge:7",
            ),
            state.operations,
        )
        assertTrue(state.operations.none { it == "expunge-all" })
        assertTrue(state.operations.none { ":8" in it })
    }

    @Test
    fun nativeMoveDoesNotCopyOrMarkMessagesDeleted() {
        val state = RecordingMailboxState(nativeMoveSupported = true)
        val client = client(state)

        client.mutate(
            credentials(),
            DovecotMessageCommand.Move(
                "INBOX",
                listOf(7),
                DovecotMailboxState(uidValidity = state.uidValidity),
                "INBOX.Archive",
            ),
        )

        assertEquals(listOf("move:INBOX.Archive:7"), state.operations)
    }

    @Test
    fun moveWithoutNativeMoveOrUidPlusFailsBeforeCopyingAnything() {
        val state = RecordingMailboxState(supportsTargetedExpunge = false)

        assertFailsWith<IllegalStateException> {
            client(state).mutate(
                credentials(),
                DovecotMessageCommand.Move(
                    "INBOX",
                    listOf(7),
                    DovecotMailboxState(uidValidity = state.uidValidity),
                    "INBOX.Archive",
                ),
            )
        }

        assertTrue(state.operations.isEmpty())
    }

    @Test
    fun aMissingUidFailsBeforeAnyPartialMutation() {
        val state = RecordingMailboxState(existingUids = setOf(7))
        val client = client(state)

        assertFailsWith<DovecotMessageMissingException> {
            client.mutate(
                credentials(),
                DovecotMessageCommand.Delete(
                    "INBOX",
                    listOf(7, 99),
                    DovecotMailboxState(uidValidity = state.uidValidity),
                ),
            )
        }

        assertTrue(state.operations.isEmpty())
    }

    @Test
    fun messageUidsAreBoundedByTheImapProtocol() {
        val state = RecordingMailboxState()

        assertFailsWith<IllegalArgumentException> {
            client(state).mutate(
                credentials(),
                DovecotMessageCommand.Delete(
                    "INBOX",
                    listOf(4_294_967_296L),
                    DovecotMailboxState(uidValidity = state.uidValidity),
                ),
            )
        }

        assertTrue(state.operations.isEmpty())
        assertEquals(0, state.storeCloseCount)
    }

    @Test
    fun mailboxProbePreservesEveryTypedAuthenticationFailure() {
        val outcomes = listOf<AuthenticationOutcome>(
            AuthenticationOutcome.MissingCredentials("password required"),
            AuthenticationOutcome.WrongPassword("authentication failed"),
            AuthenticationOutcome.MissingAccount("unknown user"),
            AuthenticationOutcome.Unavailable("connection refused"),
            AuthenticationOutcome.TimedOut("read timed out"),
        )

        outcomes.forEach { expected ->
            val client = DovecotImapClient(
                storeFactory = RecordingStoreFactory(RecordingMailboxState()),
                authenticationProbe = { expected },
            )
            val actual = client.probe(credentials())
            assertEquals(expected, actual)
            assertIs<AuthenticationOutcome>(actual)
        }
    }

    @Test
    fun loopbackImapSettingsRequireStartTlsTrustAndBoundEveryTimeout() {
        val properties = DovecotImapConnectionSettings().sessionProperties()

        assertEquals("127.0.0.1", properties.getProperty("mail.imap.host"))
        assertEquals("1143", properties.getProperty("mail.imap.port"))
        assertEquals("true", properties.getProperty("mail.imap.starttls.enable"))
        assertEquals("true", properties.getProperty("mail.imap.starttls.required"))
        assertEquals("127.0.0.1", properties.getProperty("mail.imap.ssl.trust"))
        assertEquals("true", properties.getProperty("mail.imap.peek"))
        listOf("connectiontimeout", "timeout", "writetimeout").forEach { suffix ->
            val timeout = properties.getProperty("mail.imap.$suffix").toInt()
            assertTrue(timeout in 1..30_000)
        }
    }

    @Test
    fun failuresStillCloseTheSelectedStoreAndFolder() {
        val state = RecordingMailboxState(readFailure = IllegalStateException("read failed"))
        val client = DovecotImapClient(
            storeFactory = RecordingStoreFactory(state),
            authenticationProbe = { AuthenticationOutcome.Authenticated("ok") },
        )

        assertFailsWith<IllegalStateException> {
            client.readMessage(
                AccountCredentials("alice@local.test", "alice-password"),
                "INBOX",
                7,
            )
        }

        assertEquals(1, state.storeCloseCount)
        assertEquals(1, state.folderCloseCount)
    }

    @Test
    fun connectOpenAndMutationFailuresCloseEveryCreatedResource() {
        val credentials = credentials()

        val connect = RecordingMailboxState(
            connectFailure = IllegalStateException("connect failed"),
        )
        assertFailsWith<IllegalStateException> {
            client(connect).listFolders(credentials)
        }
        assertEquals(1, connect.storeCloseCount)

        val open = RecordingMailboxState(
            openFailure = IllegalStateException("open failed"),
        )
        assertFailsWith<IllegalStateException> {
            client(open).listMessages(credentials, "INBOX")
        }
        assertEquals(1, open.storeCloseCount)
        assertEquals(0, open.folderCloseCount)

        val mutation = RecordingMailboxState(
            mutationFailure = IllegalStateException("mutation failed"),
        )
        assertFailsWith<IllegalStateException> {
            client(mutation).mutate(
                credentials,
                DovecotMessageCommand.MarkRead(
                    "INBOX",
                    listOf(7),
                    DovecotMailboxState(uidValidity = mutation.uidValidity),
                    read = true,
                ),
            )
        }
        assertEquals(1, mutation.storeCloseCount)
        assertEquals(1, mutation.folderCloseCount)
    }

    private fun client(state: RecordingMailboxState): DovecotImapClient = DovecotImapClient(
        storeFactory = RecordingStoreFactory(state),
        authenticationProbe = { AuthenticationOutcome.Authenticated("ok") },
    )

    private fun credentials(): AccountCredentials =
        AccountCredentials("alice@local.test", "alice-password")
}

private class RecordingStoreFactory(
    private val state: RecordingMailboxState,
) : DovecotImapStoreFactory {
    val credentials = mutableListOf<AccountCredentials>()

    override fun create(): DovecotImapStore = RecordingStore(state, credentials)
}

private class RecordingStore(
    private val state: RecordingMailboxState,
    private val credentials: MutableList<AccountCredentials>,
) : DovecotImapStore {
    override fun connect(credentials: AccountCredentials) {
        this.credentials += credentials
        state.connectFailure?.let { throw it }
    }

    override fun listFolders(maximumFolders: Int): List<DovecotFolder> =
        listOf(DovecotFolder("INBOX"), DovecotFolder("INBOX.Trash"))

    override fun createFolder(name: String): DovecotFolder = DovecotFolder(name)

    override fun deleteFolder(name: String) = Unit

    override fun openFolder(name: String, writable: Boolean): DovecotImapFolder =
        state.openFailure?.let { throw it } ?: RecordingFolder(state)

    override fun close() {
        state.storeCloseCount++
    }
}

private class RecordingFolder(
    private val state: RecordingMailboxState,
) : DovecotImapFolder {
    override val uidValidity: Long
        get() = state.uidValidity

    override val supportsTargetedExpunge: Boolean
        get() = state.supportsTargetedExpunge

    override fun listMessages(maximumMessages: Int): List<DovecotStoredMessage> = listOf(
        DovecotStoredMessage(
            uid = 7,
            messageId = "<fixture@local.test>",
            subject = "fixture",
            from = "sender@local.test",
            date = "Tue, 11 Aug 2026 10:00:00 +0000",
            flags = emptySet(),
        ),
    )

    override fun readMessage(uid: Long, maximumBytes: Int): String {
        state.readFailure?.let { throw it }
        require(uid == 7L)
        return "Subject: fixture\r\n\r\nbody"
    }

    override fun contains(uid: Long): Boolean = uid in state.existingUids

    override fun setFlag(uids: List<Long>, flag: String, enabled: Boolean) {
        state.mutationFailure?.let { throw it }
        state.operations += "flag:$flag:$enabled:${uids.joinToString(",")}"
    }

    override fun copy(uids: List<Long>, destination: String) {
        state.operations += "copy:$destination:${uids.joinToString(",")}"
    }

    override fun move(uids: List<Long>, destination: String): Boolean {
        if (state.nativeMoveSupported) {
            state.operations += "move:$destination:${uids.joinToString(",")}"
        }
        return state.nativeMoveSupported
    }

    override fun targetedDeleteAndExpunge(uids: List<Long>) {
        state.operations += "targeted-expunge:${uids.joinToString(",")}"
    }

    override fun close(expunge: Boolean) {
        state.folderCloseExpungeArguments += expunge
        state.folderCloseCount++
    }
}

private data class RecordingMailboxState(
    val uidValidity: Long = 4_242,
    val readFailure: RuntimeException? = null,
    val connectFailure: RuntimeException? = null,
    val openFailure: RuntimeException? = null,
    val mutationFailure: RuntimeException? = null,
    val nativeMoveSupported: Boolean = false,
    val supportsTargetedExpunge: Boolean = true,
    val existingUids: Set<Long> = setOf(7, 8),
    val operations: MutableList<String> = mutableListOf(),
    var storeCloseCount: Int = 0,
    var folderCloseCount: Int = 0,
    val folderCloseExpungeArguments: MutableList<Boolean> = mutableListOf(),
)
