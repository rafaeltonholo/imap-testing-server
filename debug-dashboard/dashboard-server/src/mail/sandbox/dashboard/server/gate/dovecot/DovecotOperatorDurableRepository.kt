package mail.sandbox.dashboard.server.gate.dovecot

import java.io.EOFException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal class DovecotOperatorProcessLockRegistry {
    private val registryLock = ReentrantLock()
    private val entries = mutableMapOf<Path, LockEntry>()

    fun <T> withLock(
        path: Path,
        block: () -> T,
    ): T {
        val entry = registryLock.withLock {
            entries.getOrPut(path, ::LockEntry).also {
                it.references += 1
            }
        }
        return try {
            entry.lock.withLock(block)
        } finally {
            registryLock.withLock {
                check(entry.references > 0) {
                    "Dovecot operator process lock registry is inconsistent"
                }
                entry.references -= 1
                if (entry.references == 0) {
                    check(entries.remove(path, entry)) {
                        "Dovecot operator process lock registry is inconsistent"
                    }
                }
            }
        }
    }

    internal fun referenceCount(path: Path): Int = registryLock.withLock {
        entries[path]?.references ?: 0
    }

    internal fun retainedLockCount(): Int = registryLock.withLock {
        entries.size
    }

    private class LockEntry {
        val lock = ReentrantLock()
        var references = 0
    }
}

internal class DovecotOperatorDurableRepository(
    private val paths: DovecotOperatorPaths,
    private val observer: DovecotOperatorStoreObserver,
) {
    fun <T> withStableLock(
        recoverTemporaries: Boolean = false,
        block: () -> T,
    ): T {
        paths.revalidate()
        ensureRuntimeRoot()
        ensureOwnedDirectory(paths.secretsDirectory)
        ensureOwnedDirectory(paths.operatorDirectory)
        return PROCESS_LOCKS.withLock(paths.lock) {
            paths.revalidate()
            requireRuntimeRoot()
            requireOwnedDirectory(paths.secretsDirectory)
            requireOwnedDirectory(paths.operatorDirectory)
            ensureOwnedFile(paths.lock)
            FileChannel.open(
                paths.lock,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            ).use { channel ->
                channel.lock().use {
                    observer.reached(
                        DovecotOperatorCommitPoint.StableLockAcquired,
                        paths.lock,
                    )
                    paths.revalidate()
                    requireRuntimeRoot()
                    requireOwnedDirectory(paths.secretsDirectory)
                    requireOwnedDirectory(paths.operatorDirectory)
                    requireOwnedRegularFile(paths.lock)
                    if (recoverTemporaries) {
                        cleanupRecognizedTemporaries()
                    } else {
                        requireNoTemporaryState()
                    }
                    block()
                }
            }
        }
    }

    fun readSlot(id: DovecotOperatorId): ByteArray =
        stableRead(paths.slot(id), MAX_SECRET_FILE_BYTES)

    fun readActiveReference(): ByteArray =
        stableRead(paths.active, MAX_ACTIVE_BYTES)

    fun readRotationIntent(): ByteArray =
        stableRead(paths.rotationIntent, MAX_ROTATION_INTENT_BYTES)

    fun readMasterUsers(): ByteArray =
        stableRead(paths.masterUsers, MAX_MASTER_FILE_BYTES)

    fun fixedPathExists(path: Path): Boolean = when {
        Files.exists(path, LinkOption.NOFOLLOW_LINKS) -> true
        Files.notExists(path, LinkOption.NOFOLLOW_LINKS) -> false
        else -> throw IllegalStateException(
            "Dovecot operator file state is indeterminate",
        )
    }

    fun requireNoTemporaryState() {
        listOf(paths.secretsDirectory, paths.operatorDirectory).forEach { directory ->
            Files.newDirectoryStream(directory).use { entries ->
                entries.forEach { candidate ->
                    repositorySafetyCheck(!isTemporaryCandidate(candidate)) {
                        "Dovecot operator temporary state requires manual recovery"
                    }
                }
            }
        }
    }

    fun deleteDurably(
        target: Path,
        before: DovecotOperatorCommitPoint,
        after: DovecotOperatorCommitPoint,
    ) {
        repositorySafetyCheck(
            target in setOf(paths.slotA, paths.slotB, paths.rotationIntent),
        ) {
            "Dovecot operator delete target is invalid"
        }
        requireOwnedRegularFile(target)
        observer.reached(before, target)
        Files.delete(target)
        fsyncOperatorDirectory(requireNotNull(target.parent))
        repositorySafetyCheck(
            Files.notExists(target, LinkOption.NOFOLLOW_LINKS),
        ) {
            "Dovecot operator delete verification failed"
        }
        observer.reached(after, target)
    }

    fun writeAtomic(
        target: Path,
        contents: ByteArray,
        before: DovecotOperatorCommitPoint,
        after: DovecotOperatorCommitPoint,
    ) {
        repositorySafetyCheck(target in temporaryTargets()) {
            "Dovecot operator write target is invalid"
        }
        val temporary = createTemporary(target)
        requireOwnedRegularFile(temporary)
        FileChannel.open(
            temporary,
            StandardOpenOption.WRITE,
            LinkOption.NOFOLLOW_LINKS,
        ).use { channel ->
            val buffer = ByteBuffer.wrap(contents)
            while (buffer.hasRemaining()) {
                if (channel.write(buffer) < 0) throw EOFException()
            }
            channel.force(true)
        }
        requireOwnedRegularFile(temporary)
        observer.reached(before, temporary)
        try {
            Files.move(
                temporary,
                target,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (unsupported: AtomicMoveNotSupportedException) {
            throw IllegalStateException(
                "Atomic Dovecot operator replacement is unavailable",
                unsupported,
            )
        }
        fsyncOperatorDirectory(requireNotNull(target.parent))
        requireOwnedRegularFile(target)
        val verified = stableRead(target, maximumBytesFor(target))
        try {
            repositorySafetyCheck(verified.contentEquals(contents)) {
                "Dovecot operator write verification failed"
            }
        } finally {
            verified.fill(0)
        }
        observer.reached(after, target)
    }

    private fun maximumBytesFor(target: Path): Int = when (target) {
        paths.active -> MAX_ACTIVE_BYTES
        paths.rotationIntent -> MAX_ROTATION_INTENT_BYTES
        paths.masterUsers -> MAX_MASTER_FILE_BYTES
        paths.slotA, paths.slotB -> MAX_SECRET_FILE_BYTES
        else -> throw IllegalStateException(
            "Dovecot operator write target is invalid",
        )
    }

    private fun createTemporary(target: Path): Path {
        repeat(MAX_TEMPORARY_ATTEMPTS) {
            val candidate = target.resolveSibling(
                "${target.fileName}.tmp-${UUID.randomUUID()}",
            )
            try {
                createOwnerOnlyFile(candidate)
                return candidate
            } catch (_: FileAlreadyExistsException) {
                // Try another restrictive UUID name.
            }
        }
        throw IllegalStateException(
            "Could not allocate a Dovecot operator temporary",
        )
    }

    private fun cleanupRecognizedTemporaries() {
        listOf(paths.secretsDirectory, paths.operatorDirectory).forEach { directory ->
            Files.newDirectoryStream(directory).use { entries ->
                entries.forEach { candidate ->
                    if (!isTemporaryCandidate(candidate)) return@forEach
                    repositorySafetyCheck(isTemporaryPath(candidate)) {
                        "Dovecot operator temporary state is unrecognized"
                    }
                    val target = requireNotNull(temporaryTarget(candidate))
                    requireOwnedRegularFile(candidate)
                    val attributes = Files.readAttributes(
                        candidate,
                        BasicFileAttributes::class.java,
                        LinkOption.NOFOLLOW_LINKS,
                    )
                    repositorySafetyCheck(
                        attributes.size() in
                            0..maximumBytesFor(target).toLong(),
                    ) {
                        "Dovecot operator temporary file is too large"
                    }
                    observer.reached(
                        DovecotOperatorCommitPoint.BeforeTemporaryDelete,
                        candidate,
                    )
                    Files.delete(candidate)
                    fsyncOperatorDirectory(directory)
                    observer.reached(
                        DovecotOperatorCommitPoint.AfterTemporaryDelete,
                        candidate,
                    )
                }
            }
        }
        requireNoTemporaryState()
    }

    private fun isTemporaryPath(path: Path): Boolean {
        val target = temporaryTarget(path) ?: return false
        val prefix = "${target.fileName}.tmp-"
        val suffix = path.fileName.toString().removePrefix(prefix)
        return CANONICAL_TEMPORARY_UUID.matches(suffix)
    }

    private fun isTemporaryCandidate(path: Path): Boolean {
        if (
            path.parent !in
            setOf(paths.secretsDirectory, paths.operatorDirectory)
        ) {
            return false
        }
        val name = path.fileName.toString()
        return temporaryTargets().any { target ->
            name.startsWith("${target.fileName}.tmp-")
        }
    }

    private fun temporaryTarget(path: Path): Path? {
        if (
            path.parent !in
            setOf(paths.secretsDirectory, paths.operatorDirectory)
        ) {
            return null
        }
        val name = path.fileName.toString()
        return temporaryTargets().singleOrNull { target ->
            name.startsWith("${target.fileName}.tmp-")
        }
    }

    private fun temporaryTargets(): List<Path> =
        listOf(
            paths.slotA,
            paths.slotB,
            paths.active,
            paths.rotationIntent,
            paths.masterUsers,
        )

    private fun stableRead(
        path: Path,
        maximumBytes: Int,
    ): ByteArray {
        requireOwnedRegularFile(path)
        val before = Files.readAttributes(
            path,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        repositorySafetyCheck(before.size() in 0..maximumBytes.toLong()) {
            "Dovecot operator file is too large"
        }
        val bytes = ByteArray(before.size().toInt())
        var offset = 0
        try {
            FileChannel.open(
                path,
                StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS,
            ).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) {
                    val count = channel.read(buffer)
                    if (count < 0) break
                    offset += count
                }
                repositorySafetyCheck(
                    offset == bytes.size &&
                        channel.read(ByteBuffer.allocate(1)) < 0,
                ) {
                    "Dovecot operator file changed while being read"
                }
            }
            val after = Files.readAttributes(
                path,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            repositorySafetyCheck(
                after.isRegularFile &&
                    before.fileKey() == after.fileKey() &&
                    before.size() == after.size() &&
                    before.lastModifiedTime() == after.lastModifiedTime(),
            ) {
                "Dovecot operator file changed while being read"
            }
            requireOwnedRegularFile(path)
            return bytes
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    private fun ensureRuntimeRoot() {
        val runtimeBase = paths.dashboardRoot.resolve(".runtime")
        if (Files.notExists(runtimeBase, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createOwnerOnlyDirectory(runtimeBase)
                fsyncOperatorDirectory(paths.dashboardRoot)
            } catch (_: FileAlreadyExistsException) {
                // A concurrent runtime owner created it; validate below.
            }
        }
        requireRuntimeDirectory(runtimeBase)
        if (Files.notExists(paths.runtimeRoot, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createOwnerOnlyDirectory(paths.runtimeRoot)
                fsyncOperatorDirectory(requireNotNull(paths.runtimeRoot.parent))
            } catch (_: FileAlreadyExistsException) {
                // A concurrent runtime owner created it; validate below.
            }
        }
        requireRuntimeRoot()
    }

    private fun requireRuntimeRoot() {
        requireRuntimeDirectory(paths.dashboardRoot.resolve(".runtime"))
        requireRuntimeDirectory(paths.runtimeRoot)
    }

    private fun requireRuntimeDirectory(path: Path) {
        repositorySafetyCheck(
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) ==
                paths.trustedOwner,
        ) {
            "Dovecot operator runtime root is unsafe"
        }
        if (supportsPosix(path)) {
            val permissions = Files.getPosixFilePermissions(
                path,
                LinkOption.NOFOLLOW_LINKS,
            )
            repositorySafetyCheck(
                PosixFilePermission.GROUP_WRITE !in permissions &&
                    PosixFilePermission.OTHERS_WRITE !in permissions,
            ) {
                "Dovecot operator runtime root permissions are unsafe"
            }
        }
    }

    private fun ensureOwnedDirectory(path: Path) {
        val parent = requireNotNull(path.parent)
        repositorySafetyCheck(
            Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(parent),
        ) {
            "Dovecot operator directory parent is unsafe"
        }
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createOwnerOnlyDirectory(path)
                fsyncOperatorDirectory(parent)
            } catch (_: FileAlreadyExistsException) {
                // A concurrent writer created it; validate below.
            }
        }
        requireOwnedDirectory(path)
    }

    private fun requireOwnedDirectory(path: Path) {
        repositorySafetyCheck(
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) ==
                paths.trustedOwner,
        ) {
            "Dovecot operator directory is unsafe"
        }
        if (supportsPosix(path)) {
            repositorySafetyCheck(
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) ==
                    DIRECTORY_PERMISSIONS,
            ) {
                "Dovecot operator directory permissions are unsafe"
            }
        }
        repositorySafetyCheck(
            Files.isReadable(path) &&
                Files.isWritable(path) &&
                Files.isExecutable(path),
        ) {
            "Dovecot operator directory access is unsafe"
        }
    }

    private fun ensureOwnedFile(path: Path) {
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createOwnerOnlyFile(path)
                FileChannel.open(
                    path,
                    StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS,
                ).use { it.force(true) }
                fsyncOperatorDirectory(requireNotNull(path.parent))
            } catch (_: FileAlreadyExistsException) {
                // A concurrent process created the stable lock; validate below.
            }
        }
        requireOwnedRegularFile(path)
    }

    private fun requireOwnedRegularFile(path: Path) {
        repositorySafetyCheck(
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) ==
                paths.trustedOwner,
        ) {
            "Dovecot operator file is unsafe"
        }
        if (supportsPosix(path)) {
            repositorySafetyCheck(
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) ==
                    FILE_PERMISSIONS,
            ) {
                "Dovecot operator file permissions are unsafe"
            }
        }
        repositorySafetyCheck(Files.isReadable(path) && Files.isWritable(path)) {
            "Dovecot operator file access is unsafe"
        }
    }

    private fun createOwnerOnlyDirectory(path: Path) {
        if (supportsPosix(requireNotNull(path.parent))) {
            Files.createDirectory(path, DIRECTORY_ATTRIBUTE)
        } else {
            Files.createDirectory(path)
            setFallbackOwnerOnly(path, directory = true)
        }
    }

    private fun createOwnerOnlyFile(path: Path) {
        if (supportsPosix(requireNotNull(path.parent))) {
            Files.createFile(path, FILE_ATTRIBUTE)
        } else {
            Files.createFile(path)
            setFallbackOwnerOnly(path, directory = false)
        }
    }

    private fun setFallbackOwnerOnly(
        path: Path,
        directory: Boolean,
    ) {
        val file = path.toFile()
        val removedRead = file.setReadable(false, false)
        val removedWrite = file.setWritable(false, false)
        val removedExecute = file.setExecutable(false, false)
        repositorySafetyCheck(
            removedRead && removedWrite && removedExecute,
        ) {
            "Could not remove broad Dovecot operator permissions"
        }
        repositorySafetyCheck(
            file.setReadable(true, true) &&
                file.setWritable(true, true),
        ) {
            "Could not set owner-only Dovecot operator permissions"
        }
        if (directory) {
            repositorySafetyCheck(file.setExecutable(true, true)) {
                "Could not set owner-only Dovecot operator permissions"
            }
        }
    }

    private fun fsyncOperatorDirectory(directory: Path) {
        try {
            FileChannel.open(directory, StandardOpenOption.READ).use {
                it.force(true)
            }
        } catch (failure: UnsupportedOperationException) {
            throw IllegalStateException(
                "Could not make Dovecot operator directory durable",
                failure,
            )
        } catch (failure: java.io.IOException) {
            throw IllegalStateException(
                "Could not make Dovecot operator directory durable",
                failure,
            )
        }
    }

    private fun supportsPosix(path: Path): Boolean =
        path.fileSystem.supportedFileAttributeViews().contains("posix")

    private inline fun repositorySafetyCheck(
        condition: Boolean,
        lazyMessage: () -> String,
    ) {
        if (!condition) throw IllegalStateException(lazyMessage())
    }

    companion object {
        private const val MAX_ACTIVE_BYTES = 1
        private const val MAX_ROTATION_INTENT_BYTES = 3
        private const val MAX_SECRET_FILE_BYTES = 256
        private const val MAX_MASTER_FILE_BYTES = 8 * 1024
        private const val MAX_TEMPORARY_ATTEMPTS = 16
        private val CANONICAL_TEMPORARY_UUID = Regex(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-" +
                "[0-9a-f]{4}-[0-9a-f]{12}",
        )
        private val PROCESS_LOCKS = DovecotOperatorProcessLockRegistry()
        private val DIRECTORY_PERMISSIONS: Set<PosixFilePermission> =
            PosixFilePermissions.fromString("rwx------")
        private val FILE_PERMISSIONS: Set<PosixFilePermission> =
            PosixFilePermissions.fromString("rw-------")
        private val DIRECTORY_ATTRIBUTE: FileAttribute<Set<PosixFilePermission>> =
            PosixFilePermissions.asFileAttribute(DIRECTORY_PERMISSIONS)
        private val FILE_ATTRIBUTE: FileAttribute<Set<PosixFilePermission>> =
            PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS)
    }
}
