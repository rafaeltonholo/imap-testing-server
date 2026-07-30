package mail.sandbox.dashboard.server.gate.dovecot

import java.io.EOFException
import java.io.PrintStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
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
import java.nio.file.attribute.UserPrincipal
import java.security.SecureRandom
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.system.exitProcess

private enum class DovecotOperatorPathPurpose {
    Production,
    Task5Proof,
    ;

    fun runtimeRoot(dashboardRoot: Path): Path = when (this) {
        Production -> dashboardRoot.resolve(".runtime")
        Task5Proof -> dashboardRoot.resolve(".runtime/task5-proof")
    }
}

internal enum class DovecotOperatorId(
    val reference: String,
    val masterUsername: String,
) {
    A(reference = "a", masterUsername = "dashboard-operator-a"),
    B(reference = "b", masterUsername = "dashboard-operator-b"),
    ;

    companion object {
        fun fromReference(value: String): DovecotOperatorId =
            entries.singleOrNull { it.reference == value }
                ?: throw IllegalStateException("Dovecot operator active reference is invalid")

        fun fromMasterUsername(value: String): DovecotOperatorId =
            entries.singleOrNull { it.masterUsername == value }
                ?: throw IllegalStateException("Dovecot operator master identity is invalid")
    }
}

internal class DovecotOperatorSecret private constructor(
    private val bytes: ByteArray,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun <T> withBytes(block: (ByteArray) -> T): T {
        check(!closed) { "Dovecot operator secret is closed" }
        return block(bytes)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        bytes.fill(0)
    }

    override fun toString(): String = "DovecotOperatorSecret(redacted)"

    companion object {
        private const val MAX_SECRET_BYTES = 256
        private val SAFE_BYTES = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                "abcdefghijklmnopqrstuvwxyz" +
                "0123456789-._~"
            ).toSet()

        fun takeOwnership(bytes: ByteArray): DovecotOperatorSecret {
            requireValid(bytes)
            return DovecotOperatorSecret(bytes)
        }

        internal fun requireValid(bytes: ByteArray) {
            require(bytes.size in 1..MAX_SECRET_BYTES) {
                "Dovecot operator secret is invalid"
            }
            require(
                bytes.all { byte ->
                    byte.toInt().toChar() in SAFE_BYTES
                },
            ) {
                "Dovecot operator secret is invalid"
            }
        }
    }
}

internal fun interface DovecotOperatorSecretGenerator {
    fun generate(): DovecotOperatorSecret
}

internal class SecureDovecotOperatorSecretGenerator(
    private val secureRandom: SecureRandom = SecureRandom(),
) : DovecotOperatorSecretGenerator {
    override fun generate(): DovecotOperatorSecret {
        val bytes = ByteArray(SECRET_LENGTH)
        try {
            bytes.indices.forEach { index ->
                bytes[index] = ALPHABET[
                    secureRandom.nextInt(ALPHABET.length)
                ].code.toByte()
            }
            return DovecotOperatorSecret.takeOwnership(bytes)
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    companion object {
        private const val SECRET_LENGTH = 48
        private const val ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    }
}

internal fun interface DovecotOperatorHashBoundary {
    fun hash(secret: DovecotOperatorSecret): String
}

internal class ExistingDovecotOperatorHashBoundary(
    private val delegate: EligibilityPasswordHasher,
) : DovecotOperatorHashBoundary {
    override fun hash(secret: DovecotOperatorSecret): String {
        var copy = ByteArray(0)
        return try {
            copy = secret.withBytes(ByteArray::copyOf)
            EligibilityPassword.takeOwnership(copy).use(delegate::hash)
        } finally {
            copy.fill(0)
        }
    }
}

internal fun interface DovecotOperatorHashVerifier {
    fun verify(
        secret: DovecotOperatorSecret,
        providerHash: String,
    ): Boolean
}

internal class ExistingDovecotOperatorHashVerifier(
    private val repositoryRoot: Path,
    private val processRunner: EligibilityProcessRunner =
        JvmEligibilityProcessRunner(),
) : DovecotOperatorHashVerifier {
    override fun verify(
        secret: DovecotOperatorSecret,
        providerHash: String,
    ): Boolean {
        EligibilityEntry.requireValidHash(providerHash)
        val processInput = secret.withBytes(::onceOverStdin)
        var result: EligibilityProcessResult? = null
        var expectedSuccess = ByteArray(0)
        var expectedMismatch = ByteArray(0)
        try {
            result = processRunner.run(
                EligibilityProcessRequest(
                    argv = VERIFY_ARGV_PREFIX + providerHash,
                    workingDirectory = repositoryRoot,
                    stdin = processInput,
                    timeout = PROCESS_TIMEOUT,
                    maximumOutputBytes = MAXIMUM_OUTPUT_BYTES,
                ),
            )
            expectedSuccess = (
                "$providerHash (verified)\n"
                ).toByteArray(StandardCharsets.US_ASCII)
            expectedMismatch = MISMATCH_STDERR.toByteArray(
                StandardCharsets.US_ASCII,
            )
            return when {
                !result.timedOut &&
                    result.exitCode == 0 &&
                    result.stdout.contentEquals(expectedSuccess) &&
                    result.stderr.isEmpty() -> true
                !result.timedOut &&
                    result.exitCode == MISMATCH_EXIT_CODE &&
                    result.stdout.isEmpty() &&
                    result.stderr.contentEquals(expectedMismatch) -> false
                else -> throw IllegalStateException(
                    "Dovecot operator password verification failed",
                )
            }
        } finally {
            processInput.fill(0)
            expectedSuccess.fill(0)
            expectedMismatch.fill(0)
            result?.stdout?.fill(0)
            result?.stderr?.fill(0)
        }
    }

    private fun onceOverStdin(secret: ByteArray): ByteArray {
        DovecotOperatorSecret.requireValid(secret)
        return ByteArray(secret.size + 1).also { input ->
            secret.copyInto(input)
            input[input.lastIndex] = '\n'.code.toByte()
        }
    }

    companion object {
        private val VERIFY_ARGV_PREFIX = listOf(
            "docker",
            "compose",
            "exec",
            "-T",
            "dovecot",
            "doveadm",
            "pw",
            "-t",
        )
        private val PROCESS_TIMEOUT = java.time.Duration.ofSeconds(30)
        private const val MAXIMUM_OUTPUT_BYTES = 16 * 1024
        private const val MISMATCH_EXIT_CODE = 75
        private const val MISMATCH_STDERR =
            "Fatal: reverse password verification check failed: " +
                "Password mismatch\n"
    }
}

internal class DovecotOperatorCredential(
    val id: DovecotOperatorId,
    private val secret: DovecotOperatorSecret,
) : AutoCloseable {
    fun <T> withSecretBytes(block: (ByteArray) -> T): T = secret.withBytes(block)

    override fun close() = secret.close()

    override fun toString(): String =
        "DovecotOperatorCredential(id=${id.name}, secret=redacted)"
}

internal class DovecotOperatorPaths private constructor(
    private val purpose: DovecotOperatorPathPurpose,
    val repositoryRoot: Path,
    val dashboardRoot: Path,
    val runtimeRoot: Path,
    val secretsDirectory: Path,
    val operatorDirectory: Path,
    val slotA: Path,
    val slotB: Path,
    val active: Path,
    val lock: Path,
    val masterUsers: Path,
    internal val trustedOwner: UserPrincipal,
) {
    fun slot(id: DovecotOperatorId): Path = when (id) {
        DovecotOperatorId.A -> slotA
        DovecotOperatorId.B -> slotB
    }

    fun revalidate() {
        requireOperatorCanonicalDirectory(repositoryRoot, "repository root")
        requireOperatorCanonicalDirectory(dashboardRoot, "dashboard root")
        requireOperatorFixedRegularFile(
            repositoryRoot.resolve("docker-compose.yml"),
            "Compose project marker",
        )
        requireOperatorFixedRegularFile(
            dashboardRoot.resolve("project.yaml"),
            "dashboard project marker",
        )
        operatorSafetyCheck(dashboardRoot.parent == repositoryRoot) {
            "Dashboard project layout is invalid"
        }
        operatorSafetyCheck(
            Files.getOwner(repositoryRoot, LinkOption.NOFOLLOW_LINKS) ==
                trustedOwner &&
                Files.getOwner(dashboardRoot, LinkOption.NOFOLLOW_LINKS) ==
                trustedOwner,
        ) {
            "Dovecot operator trusted owner changed"
        }
        operatorSafetyCheck(
            runtimeRoot == purpose.runtimeRoot(dashboardRoot) &&
                secretsDirectory == runtimeRoot.resolve("secrets") &&
                operatorDirectory == runtimeRoot.resolve("dovecot-operator") &&
                slotA == secretsDirectory.resolve("dovecot-operator-a") &&
                slotB == secretsDirectory.resolve("dovecot-operator-b") &&
                active == secretsDirectory.resolve("dovecot-operator-active") &&
                lock == secretsDirectory.resolve("dovecot-operator.lock") &&
                masterUsers == operatorDirectory.resolve("master-users"),
        ) {
            "Dovecot operator paths are invalid"
        }
    }

    override fun toString(): String = "DovecotOperatorPaths(fixed, paths=redacted)"

    companion object {
        fun production(): DovecotOperatorPaths {
            val workingDirectory = Path.of(System.getProperty("user.dir"))
                .toAbsolutePath()
                .normalize()
            val canonicalWorkingDirectory = workingDirectory.toRealPath()
            operatorSafetyCheck(canonicalWorkingDirectory == workingDirectory) {
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
                    "Run the Dovecot operator command from the canonical repository layout",
                )
            }
            return create(
                repositoryRoot,
                DovecotOperatorPathPurpose.Production,
            )
        }

        fun testing(repositoryRoot: Path): DovecotOperatorPaths =
            create(
                repositoryRoot.toAbsolutePath().normalize(),
                DovecotOperatorPathPurpose.Production,
            )

        fun task5Proof(repositoryRoot: Path): DovecotOperatorPaths =
            create(
                repositoryRoot.toAbsolutePath().normalize(),
                DovecotOperatorPathPurpose.Task5Proof,
            )

        private fun create(
            repositoryRoot: Path,
            purpose: DovecotOperatorPathPurpose,
        ): DovecotOperatorPaths {
            requireOperatorCanonicalDirectory(repositoryRoot, "repository root")
            val dashboardRoot = repositoryRoot.resolve("debug-dashboard")
            requireOperatorCanonicalDirectory(dashboardRoot, "dashboard root")
            requireOperatorFixedRegularFile(
                repositoryRoot.resolve("docker-compose.yml"),
                "Compose project marker",
            )
            requireOperatorFixedRegularFile(
                dashboardRoot.resolve("project.yaml"),
                "dashboard project marker",
            )
            val runtimeRoot = purpose.runtimeRoot(dashboardRoot)
            val secretsDirectory = runtimeRoot.resolve("secrets")
            val operatorDirectory = runtimeRoot.resolve("dovecot-operator")
            val trustedOwner = Files.getOwner(
                repositoryRoot,
                LinkOption.NOFOLLOW_LINKS,
            )
            operatorSafetyCheck(
                Files.getOwner(dashboardRoot, LinkOption.NOFOLLOW_LINKS) ==
                    trustedOwner,
            ) {
                "Dovecot operator repository ownership is inconsistent"
            }
            return DovecotOperatorPaths(
                purpose = purpose,
                repositoryRoot = repositoryRoot,
                dashboardRoot = dashboardRoot,
                runtimeRoot = runtimeRoot,
                secretsDirectory = secretsDirectory,
                operatorDirectory = operatorDirectory,
                slotA = secretsDirectory.resolve("dovecot-operator-a"),
                slotB = secretsDirectory.resolve("dovecot-operator-b"),
                active = secretsDirectory.resolve("dovecot-operator-active"),
                lock = secretsDirectory.resolve("dovecot-operator.lock"),
                masterUsers = operatorDirectory.resolve("master-users"),
                trustedOwner = trustedOwner,
            ).also(DovecotOperatorPaths::revalidate)
        }

        private fun isRepositoryRoot(path: Path): Boolean =
            isOperatorFixedRegularFile(path.resolve("docker-compose.yml")) &&
                isDashboardRoot(path.resolve("debug-dashboard"))

        private fun isDashboardRoot(path: Path): Boolean =
            isOperatorFixedRegularFile(path.resolve("project.yaml")) &&
                path.parent?.let {
                    isOperatorFixedRegularFile(it.resolve("docker-compose.yml"))
                } == true
    }
}

internal enum class DovecotOperatorCommitPoint {
    StableLockAcquired,
    BeforeSlotReplace,
    AfterSlotReplace,
    BeforeMasterReplace,
    AfterMasterReplace,
    BeforeActiveReplace,
    AfterActiveReplace,
    FinalVerified,
}

internal fun interface DovecotOperatorStoreObserver {
    fun reached(
        point: DovecotOperatorCommitPoint,
        path: Path,
    )
}

internal fun interface DovecotOperatorBootstrapper {
    fun bootstrap(): DovecotOperatorId
}

internal class DovecotOperatorCredentialStore(
    private val paths: DovecotOperatorPaths,
    private val hasher: DovecotOperatorHashBoundary,
    private val verifier: DovecotOperatorHashVerifier,
    private val generator: DovecotOperatorSecretGenerator =
        SecureDovecotOperatorSecretGenerator(),
    private val observer: DovecotOperatorStoreObserver =
        DovecotOperatorStoreObserver { _, _ -> },
) : DovecotOperatorBootstrapper {
    override fun bootstrap(): DovecotOperatorId = withStableLock {
        when (val current = readState()) {
            OperatorState.Empty -> bootstrapEmpty()
            is OperatorState.Consistent -> {
                current.secret.fill(0)
                current.id
            }
        }
    }

    fun loadActive(): DovecotOperatorCredential = withStableLock {
        when (val current = readState()) {
            OperatorState.Empty ->
                throw IllegalStateException("Dovecot operator credential is absent")
            is OperatorState.Consistent -> DovecotOperatorCredential(
                id = current.id,
                secret = DovecotOperatorSecret.takeOwnership(current.secret),
            )
        }
    }

    private fun bootstrapEmpty(): DovecotOperatorId {
        val id = DovecotOperatorId.A
        generator.generate().use { secret ->
            val hash = try {
                hasher.hash(secret).also(EligibilityEntry::requireValidHash)
            } catch (failure: IllegalArgumentException) {
                throw IllegalStateException(
                    "Dovecot operator password hashing returned an invalid result",
                    failure,
                )
            }
            secret.withBytes { bytes ->
                writeAtomic(
                    target = paths.slot(id),
                    contents = bytes,
                    before = DovecotOperatorCommitPoint.BeforeSlotReplace,
                    after = DovecotOperatorCommitPoint.AfterSlotReplace,
                )
            }

            val masterBytes = (
                "${id.masterUsername}:$hash\n"
                ).toByteArray(StandardCharsets.US_ASCII)
            try {
                writeAtomic(
                    target = paths.masterUsers,
                    contents = masterBytes,
                    before = DovecotOperatorCommitPoint.BeforeMasterReplace,
                    after = DovecotOperatorCommitPoint.AfterMasterReplace,
                )
            } finally {
                masterBytes.fill(0)
            }

            val referenceBytes = id.reference.toByteArray(StandardCharsets.US_ASCII)
            try {
                writeAtomic(
                    target = paths.active,
                    contents = referenceBytes,
                    before = DovecotOperatorCommitPoint.BeforeActiveReplace,
                    after = DovecotOperatorCommitPoint.AfterActiveReplace,
                )
            } finally {
                referenceBytes.fill(0)
            }

            when (val verified = readState()) {
                OperatorState.Empty ->
                    throw IllegalStateException(
                        "Dovecot operator post-write verification failed",
                    )
                is OperatorState.Consistent -> {
                    try {
                        operatorSafetyCheck(
                            verified.id == id &&
                                secret.withBytes(verified.secret::contentEquals),
                        ) {
                            "Dovecot operator post-write verification failed"
                        }
                    } finally {
                        verified.secret.fill(0)
                    }
                }
            }
            observer.reached(
                DovecotOperatorCommitPoint.FinalVerified,
                paths.active,
            )
            return id
        }
    }

    private fun <T> withStableLock(block: () -> T): T {
        paths.revalidate()
        ensureRuntimeRoot()
        ensureOwnedDirectory(paths.secretsDirectory)
        ensureOwnedDirectory(paths.operatorDirectory)
        val localLock = processLocks.computeIfAbsent(paths.lock) { ReentrantLock() }
        return localLock.withLock {
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
                    requireNoTemporaryState()
                    block()
                }
            }
        }
    }

    private fun readState(): OperatorState {
        requireNoTemporaryState()
        val slotAExists = fixedPathExists(paths.slotA)
        val slotBExists = fixedPathExists(paths.slotB)
        val activeExists = fixedPathExists(paths.active)
        val masterExists = fixedPathExists(paths.masterUsers)
        if (!slotAExists && !slotBExists && !activeExists && !masterExists) {
            return OperatorState.Empty
        }
        operatorSafetyCheck(
            activeExists &&
                masterExists &&
                slotAExists.xor(slotBExists),
        ) {
            "Dovecot operator credential state is inconsistent"
        }

        val activeBytes = stableRead(paths.active, MAX_ACTIVE_BYTES)
        val id = try {
            val reference = decodeAscii(activeBytes, "active reference")
            DovecotOperatorId.fromReference(reference)
        } finally {
            activeBytes.fill(0)
        }
        operatorSafetyCheck(
            fixedPathExists(paths.slot(id)) &&
                !fixedPathExists(paths.slot(id.other())),
        ) {
            "Dovecot operator credential state is inconsistent"
        }

        val secret = stableRead(paths.slot(id), MAX_SECRET_FILE_BYTES)
        try {
            try {
                DovecotOperatorSecret.requireValid(secret)
            } catch (failure: IllegalArgumentException) {
                throw IllegalStateException(
                    "Dovecot operator secret file is invalid",
                    failure,
                )
            }
            val master = readMaster()
            operatorSafetyCheck(master.id == id) {
                "Dovecot operator master and active reference disagree"
            }
            val verificationCopy = secret.copyOf()
            val verified = try {
                DovecotOperatorSecret.takeOwnership(verificationCopy).use {
                    verifier.verify(it, master.hash)
                }
            } finally {
                verificationCopy.fill(0)
            }
            operatorSafetyCheck(verified) {
                "Dovecot operator secret and master hash disagree"
            }
            return OperatorState.Consistent(id = id, secret = secret)
        } catch (failure: Throwable) {
            secret.fill(0)
            throw failure
        }
    }

    private fun readMaster(): OperatorMaster {
        val bytes = stableRead(paths.masterUsers, MAX_MASTER_FILE_BYTES)
        return try {
            operatorSafetyCheck(
                bytes.isNotEmpty() &&
                    bytes.last() == '\n'.code.toByte() &&
                    bytes.count { it == '\n'.code.toByte() } == 1 &&
                    bytes.none { it == '\r'.code.toByte() },
            ) {
                "Dovecot operator master file is invalid"
            }
            val line = decodeAscii(
                bytes.copyOf(bytes.size - 1),
                "master file",
            )
            operatorSafetyCheck(line.count { it == ':' } == 1) {
                "Dovecot operator master file is invalid"
            }
            val delimiter = line.indexOf(':')
            operatorSafetyCheck(delimiter > 0 && delimiter < line.lastIndex) {
                "Dovecot operator master file is invalid"
            }
            val id = DovecotOperatorId.fromMasterUsername(
                line.substring(0, delimiter),
            )
            val hash = line.substring(delimiter + 1)
            try {
                EligibilityEntry.requireValidHash(hash)
            } catch (failure: IllegalArgumentException) {
                throw IllegalStateException(
                    "Dovecot operator master hash is invalid",
                    failure,
                )
            }
            OperatorMaster(id, hash)
        } finally {
            bytes.fill(0)
        }
    }

    private fun writeAtomic(
        target: Path,
        contents: ByteArray,
        before: DovecotOperatorCommitPoint,
        after: DovecotOperatorCommitPoint,
    ) {
        operatorSafetyCheck(
            target in setOf(paths.slotA, paths.slotB, paths.active, paths.masterUsers),
        ) {
            "Dovecot operator write target is invalid"
        }
        val temporary = createTemporary(target)
        var replaced = false
        try {
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
            replaced = true
            fsyncOperatorDirectory(requireNotNull(target.parent))
            requireOwnedRegularFile(target)
            val verified = stableRead(target, maximumBytesFor(target))
            try {
                operatorSafetyCheck(verified.contentEquals(contents)) {
                    "Dovecot operator write verification failed"
                }
            } finally {
                verified.fill(0)
            }
            observer.reached(after, target)
        } catch (primary: Throwable) {
            if (!replaced) cleanupFailedTemporary(temporary, primary)
            throw primary
        }
    }

    private fun maximumBytesFor(target: Path): Int = when (target) {
        paths.active -> MAX_ACTIVE_BYTES
        paths.masterUsers -> MAX_MASTER_FILE_BYTES
        paths.slotA, paths.slotB -> MAX_SECRET_FILE_BYTES
        else -> throw IllegalStateException("Dovecot operator write target is invalid")
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
        throw IllegalStateException("Could not allocate a Dovecot operator temporary")
    }

    private fun cleanupFailedTemporary(
        temporary: Path,
        primary: Throwable,
    ) {
        try {
            operatorSafetyCheck(isTemporaryPath(temporary)) {
                "Dovecot operator temporary cleanup path is invalid"
            }
            requireOwnedRegularFile(temporary)
            Files.delete(temporary)
            fsyncOperatorDirectory(requireNotNull(temporary.parent))
        } catch (cleanupFailure: Throwable) {
            if (cleanupFailure !== primary) primary.addSuppressed(cleanupFailure)
        }
    }

    private fun requireNoTemporaryState() {
        listOf(paths.secretsDirectory, paths.operatorDirectory).forEach { directory ->
            Files.newDirectoryStream(directory).use { entries ->
                entries.forEach { candidate ->
                    operatorSafetyCheck(!isTemporaryPath(candidate)) {
                        "Dovecot operator temporary state requires manual recovery"
                    }
                }
            }
        }
    }

    private fun isTemporaryPath(path: Path): Boolean {
        if (path.parent !in setOf(paths.secretsDirectory, paths.operatorDirectory)) {
            return false
        }
        val name = path.fileName.toString()
        return listOf(paths.slotA, paths.slotB, paths.active, paths.masterUsers).any { target ->
            name.startsWith("${target.fileName}.tmp-")
        }
    }

    private fun fixedPathExists(path: Path): Boolean = when {
        Files.exists(path, LinkOption.NOFOLLOW_LINKS) -> true
        Files.notExists(path, LinkOption.NOFOLLOW_LINKS) -> false
        else -> throw IllegalStateException("Dovecot operator file state is indeterminate")
    }

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
        operatorSafetyCheck(before.size() in 0..maximumBytes.toLong()) {
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
                operatorSafetyCheck(offset == bytes.size && channel.read(ByteBuffer.allocate(1)) < 0) {
                    "Dovecot operator file changed while being read"
                }
            }
            val after = Files.readAttributes(
                path,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            operatorSafetyCheck(
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
        operatorSafetyCheck(
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) ==
                paths.trustedOwner,
        ) {
            "Dovecot operator runtime root is unsafe"
        }
        if (supportsOperatorPosix(path)) {
            val permissions = Files.getPosixFilePermissions(
                path,
                LinkOption.NOFOLLOW_LINKS,
            )
            operatorSafetyCheck(
                PosixFilePermission.GROUP_WRITE !in permissions &&
                    PosixFilePermission.OTHERS_WRITE !in permissions,
            ) {
                "Dovecot operator runtime root permissions are unsafe"
            }
        }
    }

    private fun ensureOwnedDirectory(path: Path) {
        val parent = requireNotNull(path.parent)
        operatorSafetyCheck(
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
        operatorSafetyCheck(
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) ==
                paths.trustedOwner,
        ) {
            "Dovecot operator directory is unsafe"
        }
        if (supportsOperatorPosix(path)) {
            operatorSafetyCheck(
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) ==
                    DIRECTORY_PERMISSIONS,
            ) {
                "Dovecot operator directory permissions are unsafe"
            }
        }
        operatorSafetyCheck(
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
        operatorSafetyCheck(
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
                !Files.isSymbolicLink(path) &&
                Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) ==
                paths.trustedOwner,
        ) {
            "Dovecot operator file is unsafe"
        }
        if (supportsOperatorPosix(path)) {
            operatorSafetyCheck(
                Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) ==
                    FILE_PERMISSIONS,
            ) {
                "Dovecot operator file permissions are unsafe"
            }
        }
        operatorSafetyCheck(Files.isReadable(path) && Files.isWritable(path)) {
            "Dovecot operator file access is unsafe"
        }
    }

    private fun createOwnerOnlyDirectory(path: Path) {
        if (supportsOperatorPosix(requireNotNull(path.parent))) {
            Files.createDirectory(path, DIRECTORY_ATTRIBUTE)
        } else {
            Files.createDirectory(path)
            setFallbackOwnerOnly(path, directory = true)
        }
    }

    private fun createOwnerOnlyFile(path: Path) {
        if (supportsOperatorPosix(requireNotNull(path.parent))) {
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
        operatorSafetyCheck(
            removedRead && removedWrite && removedExecute,
        ) {
            "Could not remove broad Dovecot operator permissions"
        }
        operatorSafetyCheck(file.setReadable(true, true) && file.setWritable(true, true)) {
            "Could not set owner-only Dovecot operator permissions"
        }
        if (directory) {
            operatorSafetyCheck(file.setExecutable(true, true)) {
                "Could not set owner-only Dovecot operator permissions"
            }
        }
    }

    private fun fsyncOperatorDirectory(directory: Path) {
        try {
            FileChannel.open(directory, StandardOpenOption.READ).use { it.force(true) }
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

    private fun decodeAscii(
        bytes: ByteArray,
        description: String,
    ): String = try {
        ASCII_DECODER.get().reset().decode(ByteBuffer.wrap(bytes)).toString()
    } catch (failure: Exception) {
        throw IllegalStateException("Dovecot operator $description is invalid", failure)
    }

    private fun DovecotOperatorId.other(): DovecotOperatorId = when (this) {
        DovecotOperatorId.A -> DovecotOperatorId.B
        DovecotOperatorId.B -> DovecotOperatorId.A
    }

    private sealed interface OperatorState {
        data object Empty : OperatorState

        class Consistent(
            val id: DovecotOperatorId,
            val secret: ByteArray,
        ) : OperatorState
    }

    private class OperatorMaster(
        val id: DovecotOperatorId,
        val hash: String,
    )

    companion object {
        private const val MAX_ACTIVE_BYTES = 1
        private const val MAX_SECRET_FILE_BYTES = 256
        private const val MAX_MASTER_FILE_BYTES = 8 * 1024
        private const val MAX_TEMPORARY_ATTEMPTS = 16
        private val processLocks = ConcurrentHashMap<Path, ReentrantLock>()
        private val DIRECTORY_PERMISSIONS: Set<PosixFilePermission> =
            PosixFilePermissions.fromString("rwx------")
        private val FILE_PERMISSIONS: Set<PosixFilePermission> =
            PosixFilePermissions.fromString("rw-------")
        private val DIRECTORY_ATTRIBUTE: FileAttribute<Set<PosixFilePermission>> =
            PosixFilePermissions.asFileAttribute(DIRECTORY_PERMISSIONS)
        private val FILE_ATTRIBUTE: FileAttribute<Set<PosixFilePermission>> =
            PosixFilePermissions.asFileAttribute(FILE_PERMISSIONS)
        private val ASCII_DECODER = ThreadLocal.withInitial {
            StandardCharsets.US_ASCII.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
        }
    }
}

internal class DovecotOperatorCredentialStoreCli(
    private val environment: Map<String, String> = System.getenv(),
    private val storeFactory: () -> DovecotOperatorBootstrapper =
        ::productionDovecotOperatorStore,
    private val task5ProofStoreFactory: () -> DovecotOperatorBootstrapper =
        ::productionTask5ProofDovecotOperatorStore,
) {
    fun execute(
        args: Array<String>,
        stdout: PrintStream,
        stderr: PrintStream,
    ): Int = try {
        val store = when {
            args.contentEquals(arrayOf("bootstrap")) -> {
                require(
                    environment["DOVECOT_LIVE_PROFILE"] != "task5-proof",
                ) {
                    "Normal operator authority is unavailable during Task 5 proof"
                }
                storeFactory()
            }
            args.contentEquals(arrayOf("bootstrap-task5-proof")) ->
                task5ProofStoreFactory()
            else -> throw IllegalArgumentException(
                "Dovecot operator command is invalid",
            )
        }
        store.bootstrap()
        stdout.println("Dovecot operator credential bootstrap complete")
        0
    } catch (_: Exception) {
        stderr.println("Dovecot operator credential command failed")
        2
    }

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            exitProcess(
                DovecotOperatorCredentialStoreCli().execute(
                    args = args,
                    stdout = System.out,
                    stderr = System.err,
                ),
            )
        }
    }
}

private fun productionDovecotOperatorStore(): DovecotOperatorCredentialStore {
    val paths = DovecotOperatorPaths.production()
    return DovecotOperatorCredentialStore(
        paths = paths,
        generator = SecureDovecotOperatorSecretGenerator(),
        hasher = ExistingDovecotOperatorHashBoundary(
            DovecotPasswordHasher(paths.repositoryRoot),
        ),
        verifier = ExistingDovecotOperatorHashVerifier(
            paths.repositoryRoot,
        ),
    )
}

private fun productionTask5ProofDovecotOperatorStore():
    DovecotOperatorCredentialStore {
    val repositoryRoot = DovecotOperatorPaths.production().repositoryRoot
    val profile = DovecotTask5ProofProfile.load(
        repositoryRoot = repositoryRoot,
    )
    profile.requirePreparedTls()
    val paths = profile.operatorPaths()
    return DovecotOperatorCredentialStore(
        paths = paths,
        generator = SecureDovecotOperatorSecretGenerator(),
        hasher = ExistingDovecotOperatorHashBoundary(
            DovecotPasswordHasher(
                paths.repositoryRoot,
                JvmEligibilityProcessRunner(
                    dockerRouting = DovecotDockerRouting.task5Proof(profile),
                ),
            ),
        ),
        verifier = ExistingDovecotOperatorHashVerifier(
            repositoryRoot = paths.repositoryRoot,
            processRunner = JvmEligibilityProcessRunner(
                dockerRouting = DovecotDockerRouting.task5Proof(profile),
            ),
        ),
    )
}

private fun requireOperatorCanonicalDirectory(
    path: Path,
    description: String,
) {
    operatorSafetyCheck(
        path.isAbsolute &&
            path.normalize() == path &&
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(path) &&
            path.toRealPath() == path,
    ) {
        "$description is invalid"
    }
}

private fun requireOperatorFixedRegularFile(
    path: Path,
    description: String,
) {
    operatorSafetyCheck(isOperatorFixedRegularFile(path)) {
        "$description is invalid"
    }
}

private fun isOperatorFixedRegularFile(path: Path): Boolean =
    Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) &&
        !Files.isSymbolicLink(path) &&
        runCatching {
            path.toRealPath(LinkOption.NOFOLLOW_LINKS) ==
                path.toAbsolutePath().normalize()
        }.getOrDefault(false)

private fun supportsOperatorPosix(path: Path): Boolean =
    path.fileSystem.supportedFileAttributeViews().contains("posix")

private inline fun operatorSafetyCheck(
    condition: Boolean,
    lazyMessage: () -> String,
) {
    if (!condition) throw IllegalStateException(lazyMessage())
}
