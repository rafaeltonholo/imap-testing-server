package mail.sandbox.dashboard.server.provider.stalwart

import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.FileTime
import java.security.MessageDigest
import java.util.Collections
import mail.sandbox.dashboard.server.provider.stalwart.credential.StalwartBorrowedSecret

internal const val PROTECTED_ACCOUNTS_SCHEMA =
    "mail-sandbox.stalwart-v016-protected-accounts.v1"
internal const val MAX_MANAGEMENT_API_KEY_BYTES = 4 * 1024

private const val MAX_PROTECTED_ACCOUNTS_BYTES = 4 * 1024
private const val MANAGEMENT_API_KEY_PREFIX_BYTES = 4
private const val MANAGEMENT_API_KEY_SUFFIX_BYTES = 38
private const val MANAGEMENT_API_KEY_BYTES =
    MANAGEMENT_API_KEY_PREFIX_BYTES + MANAGEMENT_API_KEY_SUFFIX_BYTES
private const val MAX_STALWART_ACCOUNT_ID_BYTES = 255
private val ownerDirectoryPermissions: Set<PosixFilePermission> =
    PosixFilePermissions.fromString("rwx------")
private val ownerFilePermissions: Set<PosixFilePermission> =
    PosixFilePermissions.fromString("rw-------")
private val accountIdPattern = Regex("[A-Za-z0-9_-]{1,$MAX_STALWART_ACCOUNT_ID_BYTES}")

internal class StalwartRuntimeSecretPaths private constructor(
    val managementApiKey: Path,
    val protectedAccounts: Path,
    private val projectRoot: Path,
) {
    internal fun revalidate(): Path {
        val currentRoot = validateDashboardProjectRoot(projectRoot)
        require(currentRoot == projectRoot) {
            "The dashboard project root changed"
        }
        require(
            managementApiKey ==
                projectRoot.resolve(".runtime/secrets/stalwart-management-api-key") &&
                protectedAccounts ==
                projectRoot.resolve(".runtime/stalwart/protected-accounts.json"),
        ) {
            "Stalwart runtime paths are invalid"
        }
        return currentRoot
    }

    override fun toString(): String = "StalwartRuntimeSecretPaths(fixed, paths=redacted)"

    companion object {
        fun production(dashboardProjectRoot: Path): StalwartRuntimeSecretPaths {
            val projectRoot = validateDashboardProjectRoot(dashboardProjectRoot)
            return StalwartRuntimeSecretPaths(
                managementApiKey =
                    projectRoot.resolve(".runtime/secrets/stalwart-management-api-key"),
                protectedAccounts =
                    projectRoot.resolve(".runtime/stalwart/protected-accounts.json"),
                projectRoot = projectRoot,
            )
        }
    }
}

internal class StalwartRuntimeSecrets internal constructor(
    protectedAccountIds: Set<String>,
    private val managementApiKey: StalwartBorrowedSecret,
) : AutoCloseable {
    val protectedAccountIds: Set<String> =
        Collections.unmodifiableSet(LinkedHashSet(protectedAccountIds))

    init {
        try {
            require(this.protectedAccountIds.size == 1) {
                "Protected Stalwart Account state is invalid"
            }
        } catch (failure: Throwable) {
            managementApiKey.close()
            throw failure
        }
    }

    fun <T> withManagementApiKey(block: (ByteArray) -> T): T =
        managementApiKey.withBytes(block)

    override fun close() {
        managementApiKey.close()
    }

    override fun toString(): String =
        "StalwartRuntimeSecrets(" +
            "protectedAccountCount=${protectedAccountIds.size}, managementApiKey=redacted)"
}

internal class StalwartRuntimeSecretLoader(
    private val paths: StalwartRuntimeSecretPaths,
    private val loadObserver: (StalwartRuntimeSecretLoadPoint) -> Unit = {},
) {
    fun load(): StalwartRuntimeSecrets {
        val projectRoot = paths.revalidate()
        val runtimeRoot = projectRoot.resolve(".runtime")
        val runtimeRootBefore =
            requireSecureDirectory(runtimeRoot, "Stalwart runtime root")
        val secretDirectoryBefore = requireSecureDirectory(
            paths.managementApiKey.parent,
            "Stalwart runtime secret directory",
        )
        val stateDirectoryBefore = requireSecureDirectory(
            paths.protectedAccounts.parent,
            "Stalwart runtime state directory",
        )

        val managementApiKeyFile = readStableOwnerOnlyFile(
            path = paths.managementApiKey,
            projectRoot = projectRoot,
            label = "Stalwart management API key",
            maximumBytes = MAX_MANAGEMENT_API_KEY_BYTES,
        )
        try {
            validateManagementApiKey(managementApiKeyFile.content)
            loadObserver(StalwartRuntimeSecretLoadPoint.AfterManagementKeyRead)
            val protectedFile = readStableOwnerOnlyFile(
                path = paths.protectedAccounts,
                projectRoot = projectRoot,
                label = "Stalwart protected Account state",
                maximumBytes = MAX_PROTECTED_ACCOUNTS_BYTES,
            )
            val protectedAccountIds = try {
                val parsed = parseProtectedAccountIds(protectedFile.content)
                loadObserver(StalwartRuntimeSecretLoadPoint.AfterProtectedAccountsRead)
                require(paths.revalidate() == projectRoot) {
                    "Stalwart runtime configuration changed while it was loaded"
                }
                require(
                    requireSecureDirectory(runtimeRoot, "Stalwart runtime root") ==
                        runtimeRootBefore &&
                        requireSecureDirectory(
                            paths.managementApiKey.parent,
                            "Stalwart runtime secret directory",
                        ) == secretDirectoryBefore &&
                        requireSecureDirectory(
                            paths.protectedAccounts.parent,
                            "Stalwart runtime state directory",
                        ) == stateDirectoryBefore,
                ) {
                    "Stalwart runtime directories changed while they were loaded"
                }
                revalidateStableFile(
                    original = managementApiKeyFile,
                    path = paths.managementApiKey,
                    projectRoot = projectRoot,
                    label = "Stalwart management API key",
                    maximumBytes = MAX_MANAGEMENT_API_KEY_BYTES,
                )
                revalidateStableFile(
                    original = protectedFile,
                    path = paths.protectedAccounts,
                    projectRoot = projectRoot,
                    label = "Stalwart protected Account state",
                    maximumBytes = MAX_PROTECTED_ACCOUNTS_BYTES,
                )
                parsed
            } finally {
                protectedFile.content.fill(0)
            }
            val ownedSecret =
                StalwartBorrowedSecret.takeOwnership(managementApiKeyFile.content)
            return StalwartRuntimeSecrets(
                protectedAccountIds = protectedAccountIds,
                managementApiKey = ownedSecret,
            )
        } catch (failure: Throwable) {
            managementApiKeyFile.content.fill(0)
            throw failure
        }
    }
}

internal enum class StalwartRuntimeSecretLoadPoint {
    AfterManagementKeyRead,
    AfterProtectedAccountsRead,
}

private class StableRuntimeFile(
    val content: ByteArray,
    val snapshot: RuntimeFileSnapshot,
) {
    override fun toString(): String = "StableRuntimeFile(content=redacted)"
}

private data class RuntimeFileSnapshot(
    val fileKey: Any?,
    val size: Long,
    val modified: FileTime,
    val created: FileTime,
    val permissions: Set<PosixFilePermission>?,
)

private data class RuntimeDirectorySnapshot(
    val fileKey: Any?,
    val modified: FileTime,
    val created: FileTime,
    val permissions: Set<PosixFilePermission>?,
)

private fun validateDashboardProjectRoot(requestedRoot: Path): Path {
    val root = requestedRoot.toAbsolutePath().normalize()
    require(
        Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(root) &&
            root.toRealPath() == root,
    ) {
        "The dashboard project root is invalid"
    }
    val projectMarker = root.resolve("project.yaml")
    require(
        Files.isRegularFile(projectMarker, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(projectMarker) &&
            projectMarker.toRealPath(LinkOption.NOFOLLOW_LINKS) == projectMarker,
    ) {
        "The dashboard project root is invalid"
    }
    return root
}

private fun requireSecureDirectory(
    path: Path,
    label: String,
): RuntimeDirectorySnapshot {
    require(
        path.isAbsolute &&
            path.normalize() == path &&
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            path.toRealPath() == path,
    ) {
        "$label is invalid"
    }
    val attributes = try {
        Files.readAttributes(
            path,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
    } catch (_: IOException) {
        throw IllegalArgumentException("$label is invalid")
    }
    val permissions = if (supportsPosix(path)) {
        val observed = Files.getPosixFilePermissions(path)
        require(observed == ownerDirectoryPermissions) {
            "$label is invalid"
        }
        observed
    } else {
        null
    }
    return RuntimeDirectorySnapshot(
        fileKey = attributes.fileKey(),
        modified = attributes.lastModifiedTime(),
        created = attributes.creationTime(),
        permissions = permissions,
    )
}

private fun readStableOwnerOnlyFile(
    path: Path,
    projectRoot: Path,
    label: String,
    maximumBytes: Int,
): StableRuntimeFile {
    require(
        path.isAbsolute &&
            path.normalize() == path &&
            path.startsWith(projectRoot) &&
            path != projectRoot,
    ) {
        "$label is invalid"
    }
    val parent = path.parent
        ?: throw IllegalArgumentException("$label is invalid")
    requireSecureDirectory(parent, "$label parent")

    var bytes: ByteArray? = null
    try {
        val before = runtimeFileSnapshot(path, label)
        require(before.size in 0..maximumBytes.toLong()) {
            "$label is invalid"
        }
        bytes = ByteArray(before.size.toInt())
        Files.newByteChannel(
            path,
            setOf<OpenOption>(
                StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS,
            ),
        ).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) {
                val read = channel.read(buffer)
                require(read >= 0) { "$label is invalid" }
                require(read != 0) { "$label is invalid" }
            }
            val overflow = ByteArray(1)
            try {
                require(channel.read(ByteBuffer.wrap(overflow)) == -1) {
                    "$label is invalid"
                }
            } finally {
                overflow.fill(0)
            }
        }
        val after = runtimeFileSnapshot(path, label)
        require(before == after) {
            "$label changed while it was read"
        }
        requireSecureDirectory(parent, "$label parent")
        return StableRuntimeFile(bytes, after)
    } catch (failure: Throwable) {
        bytes?.fill(0)
        when (failure) {
            is IllegalArgumentException -> throw failure
            is IOException, is SecurityException ->
                throw IllegalArgumentException("$label is invalid")
            else -> throw failure
        }
    }
}

private fun revalidateStableFile(
    original: StableRuntimeFile,
    path: Path,
    projectRoot: Path,
    label: String,
    maximumBytes: Int,
) {
    val current = readStableOwnerOnlyFile(
        path = path,
        projectRoot = projectRoot,
        label = label,
        maximumBytes = maximumBytes,
    )
    try {
        require(
            original.snapshot == current.snapshot &&
                MessageDigest.isEqual(original.content, current.content),
        ) {
            "$label changed while runtime material was loaded"
        }
    } finally {
        current.content.fill(0)
    }
}

private fun runtimeFileSnapshot(path: Path, label: String): RuntimeFileSnapshot {
    val attributes = try {
        Files.readAttributes(
            path,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
    } catch (_: IOException) {
        throw IllegalArgumentException("$label is invalid")
    }
    require(
        attributes.isRegularFile &&
            !attributes.isSymbolicLink &&
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            path.toRealPath(LinkOption.NOFOLLOW_LINKS) == path,
    ) {
        "$label is invalid"
    }
    val permissions = if (supportsPosix(path)) {
        val observed = Files.getPosixFilePermissions(path)
        require(observed == ownerFilePermissions) {
            "$label is invalid"
        }
        observed
    } else {
        null
    }
    return RuntimeFileSnapshot(
        fileKey = attributes.fileKey(),
        size = attributes.size(),
        modified = attributes.lastModifiedTime(),
        created = attributes.creationTime(),
        permissions = permissions,
    )
}

private fun supportsPosix(path: Path): Boolean =
    try {
        Files.getFileStore(path).supportsFileAttributeView("posix")
    } catch (_: IOException) {
        false
    }

private fun validateManagementApiKey(bytes: ByteArray) {
    val valid =
        bytes.size == MANAGEMENT_API_KEY_BYTES &&
            bytes[0] == 'A'.code.toByte() &&
            bytes[1] == 'P'.code.toByte() &&
            bytes[2] == 'I'.code.toByte() &&
            bytes[3] == '_'.code.toByte() &&
            bytes.indices.drop(MANAGEMENT_API_KEY_PREFIX_BYTES).all { index ->
                when (bytes[index].toInt().toChar()) {
                    in 'A'..'Z',
                    in 'a'..'z',
                    in '0'..'9',
                    '-',
                    '_',
                    -> true

                    else -> false
                }
            }
    require(valid) {
        "Stalwart management API key is invalid"
    }
}

private fun parseProtectedAccountIds(bytes: ByteArray): Set<String> {
    val text = try {
        StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: Exception) {
        throw IllegalArgumentException("Stalwart protected Account state is invalid")
    }
    val prefix = "{\"account_ids\":[\""
    val suffix = "\"],\"schema\":\"$PROTECTED_ACCOUNTS_SCHEMA\"}\n"
    require(text.startsWith(prefix) && text.endsWith(suffix)) {
        "Stalwart protected Account state is invalid"
    }
    val accountId = text.substring(prefix.length, text.length - suffix.length)
    require(
        accountIdPattern.matches(accountId) &&
            text == prefix + accountId + suffix,
    ) {
        "Stalwart protected Account state is invalid"
    }
    return setOf(accountId)
}
