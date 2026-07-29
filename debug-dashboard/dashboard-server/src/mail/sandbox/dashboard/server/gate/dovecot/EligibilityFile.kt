package mail.sandbox.dashboard.server.gate.dovecot

import java.io.EOFException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.AccessDeniedException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.GroupPrincipal
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserPrincipal
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal class EligibilityPaths private constructor(
    val repositoryRoot: Path,
    val dashboardRoot: Path,
    val runtimeRoot: Path,
    val dovecotDirectory: Path,
    val users: Path,
    val lock: Path,
    val seed: Path,
) {
    fun revalidate() {
        requireCanonicalDirectory(repositoryRoot, "repository root")
        requireCanonicalDirectory(dashboardRoot, "dashboard root")
        requireFixedRegularFile(
            repositoryRoot.resolve("docker-compose.yml"),
            "Compose project marker",
        )
        requireFixedRegularFile(
            dashboardRoot.resolve("project.yaml"),
            "dashboard project marker",
        )
        safetyCheck(dashboardRoot.parent == repositoryRoot) {
            "Dashboard project layout is invalid"
        }
        safetyCheck(
            runtimeRoot == dashboardRoot.resolve(".runtime") &&
                dovecotDirectory == runtimeRoot.resolve("dovecot") &&
                users == dovecotDirectory.resolve("users") &&
                lock == dovecotDirectory.resolve("users.lock") &&
                seed == repositoryRoot.resolve("config/users.seed"),
        ) {
            "Eligibility paths are invalid"
        }
    }

    override fun toString(): String = "EligibilityPaths(fixed, paths=redacted)"

    companion object {
        fun production(): EligibilityPaths {
            val workingDirectory = Path.of(System.getProperty("user.dir"))
                .toAbsolutePath()
                .normalize()
            val canonicalWorkingDirectory = workingDirectory.toRealPath()
            safetyCheck(canonicalWorkingDirectory == workingDirectory) {
                "Current working directory contains a symbolic path component"
            }
            val repositoryRoot = when {
                isRepositoryRoot(canonicalWorkingDirectory) -> canonicalWorkingDirectory
                isDashboardRoot(canonicalWorkingDirectory) ->
                    requireNotNull(canonicalWorkingDirectory.parent)
                canonicalWorkingDirectory.fileName?.toString() == "dashboard-server" &&
                    isDashboardRoot(requireNotNull(canonicalWorkingDirectory.parent)) ->
                    requireNotNull(canonicalWorkingDirectory.parent.parent)
                else -> throw IllegalStateException(
                    "Run the eligibility command from the canonical repository or dashboard layout",
                )
            }
            return create(repositoryRoot)
        }

        fun testing(repositoryRoot: Path): EligibilityPaths =
            create(repositoryRoot.toAbsolutePath().normalize())

        private fun create(repositoryRoot: Path): EligibilityPaths {
            requireCanonicalDirectory(repositoryRoot, "repository root")
            val dashboardRoot = repositoryRoot.resolve("debug-dashboard")
            requireCanonicalDirectory(dashboardRoot, "dashboard root")
            requireFixedRegularFile(
                repositoryRoot.resolve("docker-compose.yml"),
                "Compose project marker",
            )
            requireFixedRegularFile(
                dashboardRoot.resolve("project.yaml"),
                "dashboard project marker",
            )
            val runtimeRoot = dashboardRoot.resolve(".runtime")
            val dovecotDirectory = runtimeRoot.resolve("dovecot")
            return EligibilityPaths(
                repositoryRoot = repositoryRoot,
                dashboardRoot = dashboardRoot,
                runtimeRoot = runtimeRoot,
                dovecotDirectory = dovecotDirectory,
                users = dovecotDirectory.resolve("users"),
                lock = dovecotDirectory.resolve("users.lock"),
                seed = repositoryRoot.resolve("config/users.seed"),
            ).also(EligibilityPaths::revalidate)
        }

        private fun isRepositoryRoot(path: Path): Boolean =
            isFixedRegularFile(path.resolve("docker-compose.yml")) &&
                isDashboardRoot(path.resolve("debug-dashboard"))

        private fun isDashboardRoot(path: Path): Boolean =
            isFixedRegularFile(path.resolve("project.yaml")) &&
                path.parent?.let { isFixedRegularFile(it.resolve("docker-compose.yml")) } == true
    }
}

internal enum class EligibilityFileCommitPoint {
    BeforeReplace,
    AfterReplace,
    BeforePostWriteVerification,
    PostWriteVerified,
}

internal fun interface EligibilityFileObserver {
    fun reached(
        point: EligibilityFileCommitPoint,
        target: Path,
        temporary: Path?,
    )
}

internal class EligibilityFile(
    private val paths: EligibilityPaths,
    private val observer: EligibilityFileObserver = EligibilityFileObserver { _, _, _ -> },
) {
    fun list(): List<String> = withStableLock {
        readDocument().document.addresses()
    }

    fun isEmpty(): Boolean = withStableLock {
        !readDocument().hasContents
    }

    fun add(
        address: String,
        providerHash: String,
    ) {
        val entry = EligibilityEntry.create(address, providerHash)
        withStableLock {
            val next = readDocument().document.add(entry)
            writeAndVerify(next)
        }
    }

    fun reset(
        address: String,
        providerHash: String,
    ) {
        val entry = EligibilityEntry.create(address, providerHash)
        withStableLock {
            val next = readDocument().document.reset(entry)
            writeAndVerify(next)
        }
    }

    fun remove(address: String) {
        val canonicalAddress = EligibilityAddress.requireCanonical(address)
        withStableLock {
            val next = readDocument().document.remove(canonicalAddress)
            writeAndVerify(next)
        }
    }

    fun seed(entries: List<EligibilityEntry>) {
        require(entries.isNotEmpty()) { "Seed inventory is empty" }
        require(entries.map(EligibilityEntry::address).toSet().size == entries.size) {
            "Seed inventory contains duplicate addresses"
        }
        withStableLock {
            val current = readDocument()
            require(!current.hasContents) {
                "Runtime eligibility authority is not empty"
            }
            val seeded = entries.fold(EligibilityDocument.empty()) { document, entry ->
                document.add(entry)
            }
            writeAndVerify(seeded)
        }
    }

    private fun <T> withStableLock(block: () -> T): T {
        paths.revalidate()
        ensureSafeRuntimeRoot()
        ensureSecureDirectory(paths.dovecotDirectory)
        val localLock = processLocks.computeIfAbsent(paths.lock) { ReentrantLock() }
        return localLock.withLock {
            paths.revalidate()
            requireSafeRuntimeRoot()
            requireSecureDirectory(paths.dovecotDirectory)
            ensureSecureFile(paths.lock)
            FileChannel.open(
                paths.lock,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            ).use { channel ->
                channel.lock().use {
                    paths.revalidate()
                    requireSafeRuntimeRoot()
                    requireSecureDirectory(paths.dovecotDirectory)
                    requireSecureRegularFile(paths.lock)
                    cleanupRecognizedTemporaries()
                    block()
                }
            }
        }
    }

    private fun readDocument(): EligibilityRead {
        if (Files.notExists(paths.users, LinkOption.NOFOLLOW_LINKS)) {
            return EligibilityRead(EligibilityDocument.empty(), hasContents = false)
        }
        safetyCheck(Files.exists(paths.users, LinkOption.NOFOLLOW_LINKS)) {
            "Eligibility target state is indeterminate"
        }
        requireSecureRegularFile(paths.users)
        val before = Files.readAttributes(
            paths.users,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        safetyCheck(before.size() in 0..MAX_FILE_BYTES.toLong()) {
            "Eligibility target is too large"
        }
        val bytes = Files.readAllBytes(paths.users)
        try {
            safetyCheck(bytes.size <= MAX_FILE_BYTES) {
                "Eligibility target is too large"
            }
            val after = Files.readAttributes(
                paths.users,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            safetyCheck(
                after.isRegularFile &&
                    before.fileKey() == after.fileKey() &&
                    before.size() == after.size() &&
                    before.lastModifiedTime() == after.lastModifiedTime(),
            ) {
                "Eligibility target changed while being read"
            }
            val contents = decodeUtf8(bytes)
            val document = try {
                EligibilityDocument.parse(contents)
            } catch (failure: IllegalArgumentException) {
                throw IllegalStateException("Eligibility target contents are invalid", failure)
            }
            return EligibilityRead(document = document, hasContents = bytes.isNotEmpty())
        } finally {
            bytes.fill(0)
        }
    }

    private fun writeAndVerify(document: EligibilityDocument) {
        val expected = document.render()
        val intendedMetadata = if (Files.exists(paths.users, LinkOption.NOFOLLOW_LINKS)) {
            requireSecureRegularFile(paths.users)
            readMetadata(paths.users)
        } else {
            null
        }
        val bytes = expected.toByteArray(StandardCharsets.UTF_8)
        val temporary = createTemporary()
        try {
            if (intendedMetadata != null) {
                applyMetadata(temporary, intendedMetadata)
            }
            requireSecureRegularFile(temporary)
            FileChannel.open(
                temporary,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            ).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) {
                    if (channel.write(buffer) < 0) throw EOFException()
                }
                channel.force(true)
            }
            requireSecureRegularFile(temporary)
            val expectedMetadata = readMetadata(temporary)
            observer.reached(
                EligibilityFileCommitPoint.BeforeReplace,
                paths.users,
                temporary,
            )
            try {
                Files.move(
                    temporary,
                    paths.users,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (unsupported: AtomicMoveNotSupportedException) {
                throw IllegalStateException(
                    "Atomic eligibility replacement is unavailable",
                    unsupported,
                )
            }
            observer.reached(
                EligibilityFileCommitPoint.AfterReplace,
                paths.users,
                null,
            )
            fsyncDirectory(paths.dovecotDirectory)
            observer.reached(
                EligibilityFileCommitPoint.BeforePostWriteVerification,
                paths.users,
                null,
            )
            val verified = readDocument().document.render()
            safetyCheck(verified == expected) {
                "Eligibility post-write verification failed"
            }
            safetyCheck(readMetadata(paths.users) == expectedMetadata) {
                "Eligibility target metadata changed during replacement"
            }
            observer.reached(
                EligibilityFileCommitPoint.PostWriteVerified,
                paths.users,
                null,
            )
        } finally {
            bytes.fill(0)
        }
    }

    private fun createTemporary(): Path {
        repeat(MAX_TEMPORARY_ATTEMPTS) {
            val candidate = paths.users.resolveSibling(
                "users.tmp-${UUID.randomUUID()}",
            )
            try {
                createOwnerOnlyFile(candidate)
                return candidate
            } catch (_: FileAlreadyExistsException) {
                // Try another fixed recognizable UUID name.
            }
        }
        throw IllegalStateException("Could not allocate an eligibility temporary")
    }

    private fun cleanupRecognizedTemporaries() {
        var deleted = false
        Files.newDirectoryStream(paths.dovecotDirectory).use { entries ->
            entries.forEach { candidate ->
                if (isRecognizedTemporary(candidate.fileName.toString())) {
                    requireSecureRegularFile(candidate)
                    Files.delete(candidate)
                    deleted = true
                }
            }
        }
        if (deleted) fsyncDirectory(paths.dovecotDirectory)
    }

    private fun isRecognizedTemporary(name: String): Boolean {
        if (!name.startsWith(TEMPORARY_PREFIX)) return false
        val suffix = name.removePrefix(TEMPORARY_PREFIX)
        if (suffix.length != UUID_TEXT_LENGTH) return false
        return try {
            UUID.fromString(suffix).toString() == suffix
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun ensureSecureDirectory(path: Path) {
        val parent = requireNotNull(path.parent)
        safetyCheck(
            Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(parent),
        ) {
            "Eligibility directory parent is unsafe"
        }
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createOwnerOnlyDirectory(path)
                fsyncDirectory(parent)
            } catch (_: FileAlreadyExistsException) {
                // A concurrent writer created it; validate below.
            }
        }
        requireSecureDirectory(path)
    }

    private fun ensureSafeRuntimeRoot() {
        if (Files.notExists(paths.runtimeRoot, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createOwnerOnlyDirectory(paths.runtimeRoot)
                fsyncDirectory(paths.dashboardRoot)
            } catch (_: FileAlreadyExistsException) {
                // A concurrent runtime owner created it; validate below.
            }
        }
        requireSafeRuntimeRoot()
    }

    private fun requireSafeRuntimeRoot() {
        val path = paths.runtimeRoot
        safetyCheck(
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path),
        ) {
            "Eligibility runtime root is unsafe"
        }
        if (supportsPosix(path)) {
            val permissions = Files.getPosixFilePermissions(
                path,
                LinkOption.NOFOLLOW_LINKS,
            )
            safetyCheck(
                PosixFilePermission.OWNER_READ in permissions &&
                    PosixFilePermission.OWNER_WRITE in permissions &&
                    PosixFilePermission.OWNER_EXECUTE in permissions &&
                    PosixFilePermission.GROUP_WRITE !in permissions &&
                    PosixFilePermission.OTHERS_WRITE !in permissions,
            ) {
                "Eligibility runtime root permissions are unsafe"
            }
        }
    }

    private fun requireSecureDirectory(path: Path) {
        safetyCheck(
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path),
        ) {
            "Eligibility directory is unsafe"
        }
        if (supportsPosix(path)) {
            safetyCheck(
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) ==
                    DIRECTORY_PERMISSIONS,
            ) {
                "Eligibility directory permissions are unsafe"
            }
        }
    }

    private fun ensureSecureFile(path: Path) {
        if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createOwnerOnlyFile(path)
                FileChannel.open(
                    path,
                    StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS,
                ).use { it.force(true) }
                fsyncDirectory(path.parent)
            } catch (_: FileAlreadyExistsException) {
                // A concurrent process created the stable lock; validate below.
            }
        }
        requireSecureRegularFile(path)
    }

    private fun requireSecureRegularFile(path: Path) {
        safetyCheck(
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path),
        ) {
            "Eligibility file is unsafe"
        }
        if (supportsPosix(path)) {
            safetyCheck(
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) ==
                    FILE_PERMISSIONS,
            ) {
                "Eligibility file permissions are unsafe"
            }
        }
        safetyCheck(Files.isReadable(path) && Files.isWritable(path)) {
            "Eligibility file access is unsafe"
        }
    }

    private fun createOwnerOnlyDirectory(path: Path) {
        if (supportsPosix(path.parent)) {
            Files.createDirectory(path, DIRECTORY_ATTRIBUTE)
        } else {
            Files.createDirectory(path)
            setFallbackOwnerOnly(path, directory = true)
        }
    }

    private fun createOwnerOnlyFile(path: Path) {
        if (supportsPosix(path.parent)) {
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
        file.setReadable(false, false)
        file.setWritable(false, false)
        file.setExecutable(false, false)
        safetyCheck(file.setReadable(true, true) && file.setWritable(true, true)) {
            "Could not set owner-only eligibility permissions"
        }
        if (directory) {
            safetyCheck(file.setExecutable(true, true)) {
                "Could not set owner-only eligibility permissions"
            }
        }
    }

    private fun readMetadata(path: Path): EligibilityMetadata {
        requireSecureRegularFile(path)
        val owner = Files.getOwner(path, LinkOption.NOFOLLOW_LINKS)
        return if (supportsPosix(path)) {
            val attributes = Files.readAttributes(
                path,
                java.nio.file.attribute.PosixFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            EligibilityMetadata(
                owner = owner,
                group = attributes.group(),
                permissions = attributes.permissions(),
            )
        } else {
            EligibilityMetadata(owner = owner, group = null, permissions = null)
        }
    }

    private fun applyMetadata(
        path: Path,
        metadata: EligibilityMetadata,
    ) {
        Files.setOwner(path, metadata.owner)
        if (metadata.group != null && metadata.permissions != null) {
            val view = requireNotNull(
                Files.getFileAttributeView(
                    path,
                    PosixFileAttributeView::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                ),
            )
            view.setGroup(metadata.group)
            Files.setPosixFilePermissions(path, metadata.permissions)
        }
        safetyCheck(readMetadata(path) == metadata) {
            "Could not preserve eligibility ownership"
        }
    }

    private fun fsyncDirectory(directory: Path) {
        try {
            FileChannel.open(directory, StandardOpenOption.READ).use { it.force(true) }
        } catch (_: UnsupportedOperationException) {
            // Some JDK filesystem providers explicitly do not support directory channels.
        } catch (denied: AccessDeniedException) {
            if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
                return
            }
            throw IllegalStateException("Could not make eligibility directory durable", denied)
        }
    }

    private fun decodeUtf8(bytes: ByteArray): String = try {
        UTF8_DECODER.get().reset().decode(ByteBuffer.wrap(bytes)).toString()
    } catch (failure: Exception) {
        throw IllegalStateException("Eligibility target is not valid UTF-8", failure)
    }

    private fun supportsPosix(path: Path): Boolean =
        path.fileSystem.supportedFileAttributeViews().contains("posix")

    private data class EligibilityRead(
        val document: EligibilityDocument,
        val hasContents: Boolean,
    )

    private data class EligibilityMetadata(
        val owner: UserPrincipal,
        val group: GroupPrincipal?,
        val permissions: Set<PosixFilePermission>?,
    )

    companion object {
        private const val MAX_FILE_BYTES = 1024 * 1024
        private const val MAX_TEMPORARY_ATTEMPTS = 16
        private const val TEMPORARY_PREFIX = "users.tmp-"
        private const val UUID_TEXT_LENGTH = 36
        private val processLocks = ConcurrentHashMap<Path, ReentrantLock>()
        private val DIRECTORY_PERMISSIONS: Set<PosixFilePermission> =
            PosixFilePermissions.fromString("rwx------")
        private val FILE_PERMISSIONS: Set<PosixFilePermission> =
            PosixFilePermissions.fromString("rw-------")
        private val DIRECTORY_ATTRIBUTE: FileAttribute<Set<PosixFilePermission>> =
            PosixFilePermissions.asFileAttribute(DIRECTORY_PERMISSIONS)
        private val FILE_ATTRIBUTE: FileAttribute<Set<PosixFilePermission>> =
            PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS)
        private val UTF8_DECODER = ThreadLocal.withInitial {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
        }
    }
}

private fun requireCanonicalDirectory(
    path: Path,
    description: String,
) {
    safetyCheck(
        path.isAbsolute &&
            path.normalize() == path &&
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            path.toRealPath() == path,
    ) {
        "$description is invalid"
    }
}

private fun requireFixedRegularFile(
    path: Path,
    description: String,
) {
    safetyCheck(isFixedRegularFile(path)) {
        "$description is invalid"
    }
}

private fun isFixedRegularFile(path: Path): Boolean =
    Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
        !Files.isSymbolicLink(path) &&
        runCatching {
            path.toRealPath(LinkOption.NOFOLLOW_LINKS) == path.toAbsolutePath().normalize()
        }.getOrDefault(false)

private inline fun safetyCheck(
    condition: Boolean,
    lazyMessage: () -> String,
) {
    if (!condition) throw IllegalStateException(lazyMessage())
}
