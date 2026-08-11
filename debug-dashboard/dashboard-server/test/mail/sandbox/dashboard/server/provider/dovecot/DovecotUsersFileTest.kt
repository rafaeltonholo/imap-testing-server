package mail.sandbox.dashboard.server.provider.dovecot

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DovecotUsersFileTest {
    @Test
    fun canonicalRecordsRoundTripAndExposePlainPasswords() = withFixture { fixture ->
        fixture.writeUsers(
            "dev@local.test:{PLAIN}secret::::::\n" +
                "a.b+tag@sub.local.test:{PLAIN}another::::::\n",
        )

        val records = fixture.file().list()

        assertEquals(
            listOf("dev@local.test", "a.b+tag@sub.local.test"),
            records.map(DovecotUserRecord::address),
        )
        assertEquals(listOf("secret", "another"), records.map { it.plainPasswordOrNull() })
        assertEquals("{PLAIN}secret", records.first().passwordField)
    }

    @Test
    fun createChangeAndAuthOnlyDeletePreserveUnrelatedRecords() = withFixture { fixture ->
        val original =
            "unrelated@local.test:{PLAIN}keep-me::::::\n" +
                "existing@local.test:{PLAIN}unchanged::::::\n"
        fixture.writeUsers(original)
        val mailbox = fixture.root.resolve("vmail/new@local.test/Maildir").createDirectories()
        val sentinel = mailbox.resolve("message")
        sentinel.writeText("preserve")

        val file = fixture.file()
        file.create("new@local.test", "created")
        assertEquals(
            original + "new@local.test:{PLAIN}created::::::\n",
            fixture.users.readText(),
        )

        file.changePassword("new@local.test", "changed")
        assertEquals(
            original + "new@local.test:{PLAIN}changed::::::\n",
            fixture.users.readText(),
        )

        file.delete("new@local.test")
        assertEquals(original, fixture.users.readText())
        assertEquals("preserve", sentinel.readText())
        assertEquals("rw-------", fixture.mode(fixture.users))
        assertEquals("rw-------", fixture.mode(fixture.lock))
    }

    @Test
    fun createCanInitializeAnAbsentAuthorityWithCanonicalMode() = withFixture { fixture ->
        fixture.file().create("first@local.test", "secret")

        assertEquals(
            "first@local.test:{PLAIN}secret::::::\n",
            fixture.users.readText(),
        )
        assertEquals("rw-------", fixture.mode(fixture.users))
    }

    @Test
    fun operationSemanticsRejectDuplicatesAndMissingTargets() = withFixture { fixture ->
        fixture.writeUsers("dev@local.test:{PLAIN}secret::::::\n")
        val file = fixture.file()

        assertFailsWith<DovecotUsersFileException> {
            file.create("dev@local.test", "different")
        }
        assertFailsWith<DovecotUsersFileException> {
            file.changePassword("missing@local.test", "different")
        }
        assertFailsWith<DovecotUsersFileException> {
            file.delete("missing@local.test")
        }

        assertEquals("dev@local.test:{PLAIN}secret::::::\n", fixture.users.readText())
    }

    @Test
    fun malformedAuthorityIsRejectedWithoutBeingOverwritten() = withFixture { fixture ->
        val malformed = "dev@local.test:{PLAIN}secret:::::\n"
        fixture.writeUsers(malformed)

        assertFailsWith<DovecotUsersFileException> {
            fixture.file().changePassword("dev@local.test", "new")
        }

        assertEquals(malformed, fixture.users.readText())
        assertTrue(
            fixture.root.toFile().listFiles().orEmpty()
                .none { it.name.startsWith("users.tmp-") },
        )
    }

    @Test
    fun parserRejectsEveryNonCanonicalPythonAuthorityShape() = withFixture { fixture ->
        listOf(
            "Dev@local.test:{PLAIN}secret::::::\n",
            "dev@local.test:{PLAIN}secret::::::\ndev@local.test:{PLAIN}other::::::\n",
            "dev@local.test:{ARGON2ID}hash::::::\n",
            "dev@local.test:{PLAIN}secret::::::",
            "dev@local.test:{PLAIN}secret::::::\r\n",
            "# comment\n",
            "\n",
        ).forEach { document ->
            fixture.writeUsers(document)
            assertFailsWith<DovecotUsersFileException>(document) {
                fixture.file().list()
            }
        }

        Files.write(fixture.users, byteArrayOf(0xc3.toByte(), 0x28))
        Files.setPosixFilePermissions(
            fixture.users,
            PosixFilePermissions.fromString("rw-------"),
        )
        assertFailsWith<DovecotUsersFileException> { fixture.file().list() }
    }

    @Test
    fun parserMatchesPythonSplitlinesForEveryAdditionalLineBoundary() =
        withFixture { fixture ->
            PYTHON_ADDITIONAL_LINE_BOUNDARIES.forEach { boundary ->
                val password = "before${boundary}after"
                fixture.writeUsers("dev@local.test:{PLAIN}$password::::::\n")
                assertFailsWith<DovecotUsersFileException>("U+${boundary.code.toString(16)}") {
                    fixture.file().list()
                }
                fixture.writeUsers("dev@local.test:{PLAIN}old::::::\n")
                assertFailsWith<DovecotUsersFileException>("U+${boundary.code.toString(16)}") {
                    fixture.file().changePassword("dev@local.test", password)
                }
            }
        }

    @Test
    fun nonCanonicalAddressesPasswordsModesAndSymlinksFailClosed() = withFixture { fixture ->
        fixture.writeUsers("dev@local.test:{PLAIN}secret::::::\n")
        val file = fixture.file()

        listOf("Dev@local.test", "dev@localhost", "bad address@local.test").forEach { address ->
            assertFailsWith<DovecotUsersFileException>(address) {
                file.create(address, "secret")
            }
        }
        listOf("", "colon:value", "line\nvalue", "nul\u0000value").forEach { password ->
            assertFailsWith<DovecotUsersFileException>(password) {
                file.changePassword("dev@local.test", password)
            }
        }

        Files.setPosixFilePermissions(
            fixture.users,
            PosixFilePermissions.fromString("rw-r--r--"),
        )
        assertFailsWith<DovecotUsersFileException> { file.list() }

        Files.delete(fixture.users)
        val outside = fixture.root.resolve("outside")
        outside.writeText("dev@local.test:{PLAIN}outside::::::\n")
        Files.createSymbolicLink(fixture.users, outside)
        assertFailsWith<DovecotUsersFileException> {
            file.changePassword("dev@local.test", "changed")
        }
        assertEquals("dev@local.test:{PLAIN}outside::::::\n", outside.readText())
    }

    @Test
    fun replacementUsesATemporaryFileBesideTheAuthority() = withFixture { fixture ->
        fixture.writeUsers("dev@local.test:{PLAIN}old::::::\n")
        val observations = mutableListOf<Triple<Path, Path, String>>()
        val file = fixture.file { temporary, destination ->
            observations += Triple(temporary, destination, destination.readText())
            assertEquals(fixture.root, temporary.parent)
            assertEquals("rw-------", fixture.mode(temporary))
        }

        file.changePassword("dev@local.test", "new")

        assertEquals(1, observations.size)
        assertEquals(fixture.users, observations.single().second)
        assertEquals("dev@local.test:{PLAIN}old::::::\n", observations.single().third)
        assertEquals("dev@local.test:{PLAIN}new::::::\n", fixture.users.readText())
        assertTrue(
            fixture.root.toFile().listFiles().orEmpty()
                .none { it.name.startsWith("users.tmp-") },
        )
    }

    @Test
    fun pendingPythonMutationJournalPreventsKotlinMutation() = withFixture { fixture ->
        fixture.writeUsers("dev@local.test:{PLAIN}old::::::\n")
        fixture.lock.writeText(
            "users-mutation-journal-v1 " +
                "before=sha256:${"0".repeat(64)} after=sha256:${"1".repeat(64)}\n",
        )
        Files.setPosixFilePermissions(
            fixture.lock,
            PosixFilePermissions.fromString("rw-------"),
        )

        assertFailsWith<DovecotUsersFileException> {
            fixture.file().changePassword("dev@local.test", "new")
        }

        assertEquals("dev@local.test:{PLAIN}old::::::\n", fixture.users.readText())
        assertTrue(fixture.lock.readText().startsWith("users-mutation-journal-v1 "))
    }

    @Test
    fun providerVerificationRunsUnderTheLockAndClearsTheSharedJournal() =
        withFixture { fixture ->
            fixture.writeUsers("dev@local.test:{PLAIN}old::::::\n")
            var observedJournal = ""

            fixture.file().changePassword("dev@local.test", "new") {
                assertEquals("dev@local.test:{PLAIN}new::::::\n", fixture.users.readText())
                observedJournal = fixture.lock.readText()
            }

            assertTrue(observedJournal.matches(JOURNAL_PATTERN))
            assertEquals("", fixture.lock.readText())
        }

    @Test
    fun failedProviderVerificationRetainsARecoverablePythonJournal() = withFixture { fixture ->
        fixture.writeUsers("dev@local.test:{PLAIN}old::::::\n")

        assertFailsWith<DovecotUsersFileException> {
            fixture.file().changePassword("dev@local.test", "new") {
                error("provider unavailable")
            }
        }

        assertEquals("dev@local.test:{PLAIN}new::::::\n", fixture.users.readText())
        assertTrue(fixture.lock.readText().matches(JOURNAL_PATTERN))
        assertFailsWith<DovecotUsersFileException> {
            fixture.file().changePassword("dev@local.test", "another")
        }
    }

    @Test
    fun pythonFcntlLockBlocksKotlinMutationUntilRelease() = withFixture { fixture ->
        fixture.writeUsers("dev@local.test:{PLAIN}old::::::\n")
        val script = """
            import fcntl, os, sys
            descriptor = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.lockf(descriptor, fcntl.LOCK_EX)
                print("locked", flush=True)
                sys.stdin.readline()
            finally:
                os.close(descriptor)
        """.trimIndent()
        val process = ProcessBuilder("python3", "-u", "-c", script, fixture.lock.toString())
            .redirectErrorStream(true)
            .start()
        val readers = Executors.newSingleThreadExecutor()
        val mutators = Executors.newSingleThreadExecutor()
        try {
            val ready = readers.submit<String> { process.inputStream.bufferedReader().readLine() }
            assertEquals("locked", ready.get(5, TimeUnit.SECONDS))

            val mutation = mutators.submit<Unit> {
                fixture.file().changePassword("dev@local.test", "new")
            }
            Thread.sleep(200)
            assertFalse(mutation.isDone, "Kotlin writer must wait for Python's users.lock")

            process.outputStream.bufferedWriter().use { writer ->
                writer.newLine()
                writer.flush()
            }
            mutation.get(5, TimeUnit.SECONDS)
            assertTrue(process.waitFor(5, TimeUnit.SECONDS))
            assertEquals(0, process.exitValue())
            assertEquals("dev@local.test:{PLAIN}new::::::\n", fixture.users.readText())
        } finally {
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
            readers.shutdownNow()
            mutators.shutdownNow()
        }
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val root = createTempDirectory("dovecot-users-file").toRealPath()
        try {
            block(Fixture(root))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private class Fixture(val root: Path) {
        val users: Path = root.resolve("users")
        val lock: Path = root.resolve("users.lock")

        fun file(
            beforeAtomicReplace: (Path, Path) -> Unit = { _, _ -> },
        ): DovecotUsersFile = DovecotUsersFile(users, beforeAtomicReplace)

        fun writeUsers(document: String) {
            users.writeText(document)
            Files.setPosixFilePermissions(
                users,
                PosixFilePermissions.fromString("rw-------"),
            )
        }

        fun mode(path: Path): String = PosixFilePermissions.toString(
            Files.getPosixFilePermissions(path),
        )
    }

    private companion object {
        val PYTHON_ADDITIONAL_LINE_BOUNDARIES = listOf(
            '\u000b',
            '\u000c',
            '\u001c',
            '\u001d',
            '\u001e',
            '\u0085',
            '\u2028',
            '\u2029',
        )
        val JOURNAL_PATTERN = Regex(
            "users-mutation-journal-v1 " +
                "before=sha256:[0-9a-f]{64} after=sha256:[0-9a-f]{64}\\n",
        )
    }
}
