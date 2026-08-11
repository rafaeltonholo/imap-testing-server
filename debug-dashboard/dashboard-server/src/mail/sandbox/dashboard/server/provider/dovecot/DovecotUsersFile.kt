package mail.sandbox.dashboard.server.provider.dovecot

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal data class DovecotUserRecord(
    val address: String,
    val passwordField: String,
) {
    fun plainPasswordOrNull(): String? = passwordField.removePrefix(PLAIN_PREFIX)
        .takeIf { passwordField.startsWith(PLAIN_PREFIX) }
}

internal class DovecotUsersFileException(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

/**
 * The Kotlin writer for the repository's canonical Dovecot passwd-file authority.
 *
 * Its sidecar lock is intentionally the same POSIX record lock used by
 * `scripts/users_file.py`; a non-empty lock file is a pending Python mutation journal and
 * is never discarded by this writer.
 */
internal class DovecotUsersFile(
    usersPath: Path,
    private val beforeAtomicReplace: (temporary: Path, destination: Path) -> Unit = { _, _ -> },
) {
    private val usersPath = usersPath.also { path ->
        if (!path.isAbsolute || path.normalize() != path) {
            throw DovecotUsersFileException("Dovecot users path must be absolute and normalized")
        }
    }
    private val lockPath = this.usersPath.resolveSibling("${this.usersPath.fileName}.lock")
    private val inProcessLock = locks.computeIfAbsent(lockPath) { ReentrantLock() }

    fun list(): List<DovecotUserRecord> = translateFailure("read") {
        readValidated(requirePresent = true)
    }

    fun create(
        address: String,
        password: String,
        verifyProjection: () -> Unit,
    ) {
        val replacement = record(address, password)
        mutate(
            transform = { records ->
                if (records.any { it.address == replacement.address }) {
                    fail("Dovecot account already exists")
                }
                records + replacement
            },
            verifyProjection = verifyProjection,
        )
    }

    fun changePassword(
        address: String,
        password: String,
        verifyProjection: () -> Unit,
    ) {
        val replacement = record(address, password)
        mutate(
            transform = { records ->
                val index = records.indexOfFirst { it.address == replacement.address }
                if (index < 0) fail("Dovecot account was not found")
                records.toMutableList().also { it[index] = replacement }
            },
            verifyProjection = verifyProjection,
        )
    }

    fun delete(address: String, verifyProjection: () -> Unit) {
        validateAddress(address)
        mutate(
            transform = { records ->
                if (records.none { it.address == address }) {
                    fail("Dovecot account was not found")
                }
                records.filterNot { it.address == address }
            },
            verifyProjection = verifyProjection,
        )
    }

    private fun mutate(
        transform: (List<DovecotUserRecord>) -> List<DovecotUserRecord>,
        verifyProjection: () -> Unit,
    ) {
        translateFailure("mutate") {
            requireSafeParent()
            inProcessLock.withLock {
                ensureLockFile()
                FileChannel.open(
                    lockPath,
                    setOf(
                        StandardOpenOption.READ,
                        StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS,
                    ),
                ).use { channel ->
                    channel.lock().use {
                        requireSafeRegularFile(lockPath, requireMode = true)
                        if (channel.size() != 0L) {
                            fail(
                                "Dovecot users verification is pending; " +
                                    "run scripts/users_file.py verify first",
                            )
                        }
                        val existed = Files.exists(usersPath, LinkOption.NOFOLLOW_LINKS)
                        val current = readValidated(requirePresent = false)
                        val updated = transform(current)
                        val before = if (existed) {
                            serialize(current).toByteArray(StandardCharsets.UTF_8)
                        } else {
                            null
                        }
                        val after = serialize(updated).toByteArray(StandardCharsets.UTF_8)
                        try {
                            if (before?.contentEquals(after) != true) {
                                writeLockState(channel, journal(before, after))
                                try {
                                    writeAtomic(after)
                                } catch (failure: Exception) {
                                    handleWriteFailure(channel, before, after, failure)
                                }
                            }
                            try {
                                verifyProjection()
                            } catch (failure: Exception) {
                                throw DovecotUsersFileException(
                                    "Dovecot users mutation is durable, but provider " +
                                        "verification is pending",
                                    failure,
                                )
                            }
                            writeLockState(channel, "")
                        } finally {
                            before?.fill(0)
                            after.fill(0)
                        }
                    }
                }
            }
        }
    }

    private fun readValidated(requirePresent: Boolean): List<DovecotUserRecord> {
        requireSafeParent()
        if (!Files.exists(usersPath, LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(usersPath)) fail("Dovecot users authority is a symlink")
            if (requirePresent) fail("Dovecot users authority is missing")
            return emptyList()
        }
        requireSafeRegularFile(usersPath, requireMode = true)
        val raw = Files.readAllBytes(usersPath)
        val document = try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw))
                .toString()
        } catch (failure: Exception) {
            throw DovecotUsersFileException("Dovecot users authority is not valid UTF-8", failure)
        } finally {
            raw.fill(0)
        }
        return parse(document)
    }

    private fun parse(document: String): List<DovecotUserRecord> {
        if (document.any(PYTHON_NON_LF_LINE_BOUNDARIES::contains)) {
            fail("Dovecot users authority contains a non-canonical line boundary")
        }
        val lines = when {
            document.isEmpty() -> emptyList()
            !document.endsWith('\n') -> fail("Dovecot users authority is not canonical")
            else -> document.dropLast(1).split('\n')
        }
        val records = lines.mapIndexed { index, line ->
            val fields = line.split(':')
            if (fields.size != FIELD_COUNT || fields.drop(2).any(String::isNotEmpty)) {
                fail("Dovecot users line ${index + 1} is not a canonical eight-field record")
            }
            DovecotUserRecord(fields[0], fields[1]).also(::validateRecord)
        }
        val duplicates = records.groupingBy(DovecotUserRecord::address)
            .eachCount()
            .filterValues { it > 1 }
        if (duplicates.isNotEmpty()) fail("Dovecot users authority contains duplicate accounts")
        if (serialize(records) != document) fail("Dovecot users authority is not canonical")
        return records
    }

    private fun serialize(records: List<DovecotUserRecord>): String {
        val seen = hashSetOf<String>()
        return buildString {
            records.forEach { record ->
                validateRecord(record)
                if (!seen.add(record.address)) {
                    fail("Dovecot users authority contains duplicate accounts")
                }
                append(record.address)
                append(':')
                append(record.passwordField)
                append("::::::\n")
            }
        }
    }

    private fun writeAtomic(content: ByteArray) {
        var temporary: Path? = null
        try {
            temporary = Files.createTempFile(
                usersPath.parent,
                "${usersPath.fileName}.tmp-",
                null,
                PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS),
            )
            Files.setPosixFilePermissions(temporary, FILE_PERMISSIONS)
            FileChannel.open(
                temporary,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING,
            ).use { channel ->
                val buffer = ByteBuffer.wrap(content)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            beforeAtomicReplace(temporary, usersPath)
            try {
                Files.move(
                    temporary,
                    usersPath,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (failure: AtomicMoveNotSupportedException) {
                throw DovecotUsersFileException(
                    "Dovecot users authority requires an atomic same-directory replacement",
                    failure,
                )
            }
            temporary = null
            forceDirectoryWhereSupported(usersPath.parent)
            requireSafeRegularFile(usersPath, requireMode = true)
        } finally {
            temporary?.let { runCatching { Files.deleteIfExists(it) } }
        }
    }

    private fun handleWriteFailure(
        lockChannel: FileChannel,
        before: ByteArray?,
        after: ByteArray,
        failure: Exception,
    ): Nothing {
        val active = activeAuthorityBytes()
        try {
            when {
                equalAuthority(active, before) -> {
                    writeLockState(lockChannel, "")
                    throw DovecotUsersFileException(
                        "Dovecot users mutation was not applied; safe to retry",
                        failure,
                    )
                }
                equalAuthority(active, after) -> throw DovecotUsersFileException(
                    "Dovecot users mutation is durable; provider verification is pending",
                    failure,
                )
                else -> throw DovecotUsersFileException(
                    "Dovecot users mutation outcome is indeterminate; verification is pending",
                    failure,
                )
            }
        } finally {
            active?.fill(0)
        }
    }

    private fun activeAuthorityBytes(): ByteArray? {
        if (!Files.exists(usersPath, LinkOption.NOFOLLOW_LINKS)) return null
        return serialize(readValidated(requirePresent = true)).toByteArray(StandardCharsets.UTF_8)
    }

    private fun equalAuthority(left: ByteArray?, right: ByteArray?): Boolean = when {
        left == null || right == null -> left == null && right == null
        else -> left.contentEquals(right)
    }

    private fun journal(before: ByteArray?, after: ByteArray): String {
        val beforeField = before?.let { "sha256:${digest(it)}" } ?: "absent"
        return "$JOURNAL_PREFIX before=$beforeField after=sha256:${digest(after)}\n"
    }

    private fun digest(content: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(content)
        .joinToString(separator = "") { byte -> "%02x".format(byte) }

    private fun writeLockState(channel: FileChannel, state: String) {
        val encoded = state.toByteArray(StandardCharsets.US_ASCII)
        try {
            channel.position(0)
            channel.truncate(0)
            val buffer = ByteBuffer.wrap(encoded)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        } finally {
            encoded.fill(0)
        }
    }

    private fun ensureLockFile() {
        if (Files.isSymbolicLink(lockPath)) fail("Dovecot users lock is a symlink")
        if (!Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.createFile(
                    lockPath,
                    PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS),
                )
            } catch (_: java.nio.file.FileAlreadyExistsException) {
                // Another local writer won creation; validate the resulting path below.
            }
        }
        requireSafeRegularFile(lockPath, requireMode = true)
    }

    private fun requireSafeParent() {
        val parent = usersPath.parent ?: fail("Dovecot users authority has no parent")
        if (Files.isSymbolicLink(parent) || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            fail("Dovecot users authority parent is unsafe")
        }
    }

    private fun requireSafeRegularFile(path: Path, requireMode: Boolean) {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            fail("Dovecot users path is not a regular file")
        }
        if (
            requireMode &&
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) != FILE_PERMISSIONS
        ) {
            fail("Dovecot users path must have mode 0600")
        }
    }

    private fun record(address: String, password: String): DovecotUserRecord =
        DovecotUserRecord(address, "$PLAIN_PREFIX$password").also(::validateRecord)

    private fun validateRecord(record: DovecotUserRecord) {
        validateAddress(record.address)
        if (!record.passwordField.startsWith(PLAIN_PREFIX)) {
            fail("Dovecot password scheme is unsupported")
        }
        val password = record.passwordField.removePrefix(PLAIN_PREFIX)
        if (
            password.isEmpty() ||
            password.any { character ->
                character == '\u0000' ||
                    character == '\n' ||
                    character == ':' ||
                    character in PYTHON_NON_LF_LINE_BOUNDARIES
            }
        ) {
            fail("Dovecot PLAIN password is empty or unsafe")
        }
    }

    private fun validateAddress(address: String) {
        requireCanonicalDovecotAddress(address)
    }

    private fun forceDirectoryWhereSupported(directory: Path) {
        try {
            FileChannel.open(directory, StandardOpenOption.READ).use { it.force(true) }
        } catch (_: UnsupportedOperationException) {
            // Some JVM/filesystem combinations cannot open or force a directory channel.
        }
    }

    private inline fun <T> translateFailure(operation: String, block: () -> T): T = try {
        block()
    } catch (failure: DovecotUsersFileException) {
        throw failure
    } catch (failure: Exception) {
        throw DovecotUsersFileException("Could not $operation the Dovecot users authority", failure)
    }

    private fun fail(message: String): Nothing = throw DovecotUsersFileException(message)

    private companion object {
        const val PLAIN_PREFIX = "{PLAIN}"
        const val JOURNAL_PREFIX = "users-mutation-journal-v1"
        const val FIELD_COUNT = 8
        val FILE_PERMISSIONS: Set<PosixFilePermission> =
            PosixFilePermissions.fromString("rw-------")
        val locks = ConcurrentHashMap<Path, ReentrantLock>()
    }
}

private const val PLAIN_PREFIX = "{PLAIN}"

private val PYTHON_NON_LF_LINE_BOUNDARIES = setOf(
    '\r',
    '\u000b',
    '\u000c',
    '\u001c',
    '\u001d',
    '\u001e',
    '\u0085',
    '\u2028',
    '\u2029',
)

private val DOVECOT_ADDRESS_PATTERN = Regex(
    "[a-z0-9!#\$%&'*+/=?^_`{|}~-]+" +
        "(?:\\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@" +
        "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" +
        "(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+",
)

internal fun requireCanonicalDovecotAddress(address: String): String {
    if (address != address.lowercase(Locale.ROOT) || !DOVECOT_ADDRESS_PATTERN.matches(address)) {
        throw DovecotUsersFileException(
            "Dovecot account address is malformed or non-canonical",
        )
    }
    return address
}
