package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.io.EOFException
import java.io.IOException
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
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.IdentityHashMap
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.withLock

internal class CredentialStorePaths private constructor(
    val runtimeRoot: Path,
    val ciphertext: Path,
    val key: Path,
    val lock: Path,
    val quarantine: Path,
    internal val trustedRoot: Path,
) {
    companion object {
        fun production(dashboardProjectRoot: Path): CredentialStorePaths {
            val projectRoot = validateExistingRoot(dashboardProjectRoot)
            val projectMarker = projectRoot.resolve("project.yaml")
            require(
                Files.isRegularFile(projectMarker, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(projectMarker),
            ) {
                "The dashboard project root is invalid"
            }
            return fromRuntimeRoot(
                runtimeRoot = projectRoot.resolve(".runtime"),
                trustedRoot = projectRoot,
            )
        }

        fun testing(runtimeRoot: Path): CredentialStorePaths {
            val absolute = runtimeRoot.toAbsolutePath().normalize()
            val parent = requireNotNull(absolute.parent) {
                "Credential runtime parent is absent"
            }
            val trustedRoot = validateExistingRoot(parent)
            return fromRuntimeRoot(
                runtimeRoot = trustedRoot.resolve(absolute.fileName),
                trustedRoot = trustedRoot,
            )
        }

        private fun validateExistingRoot(root: Path): Path {
            val absolute = root.toAbsolutePath().normalize()
            require(
                Files.isDirectory(absolute, LinkOption.NOFOLLOW_LINKS) &&
                    !Files.isSymbolicLink(absolute),
            ) {
                "Credential store root is invalid"
            }
            val canonical = absolute.toRealPath()
            require(canonical == absolute) {
                "Credential store root contains a symbolic path component"
            }
            return canonical
        }

        private fun fromRuntimeRoot(
            runtimeRoot: Path,
            trustedRoot: Path,
        ): CredentialStorePaths {
            val stalwartDirectory = runtimeRoot.resolve("stalwart")
            return CredentialStorePaths(
                runtimeRoot = runtimeRoot,
                ciphertext = stalwartDirectory.resolve("app-passwords.v1.enc"),
                key = runtimeRoot.resolve("keys/stalwart-app-passwords.v1.key"),
                lock = stalwartDirectory.resolve("app-passwords.v1.lock"),
                quarantine = stalwartDirectory.resolve("quarantine"),
                trustedRoot = trustedRoot,
            )
        }
    }
}

internal enum class CredentialStoreCommitPoint {
    BeforeReplace,
    AfterReplace,
    BeforeFailIfExistsPublish,
    AfterFailIfExistsPublish,
    AfterQuarantineSourceDelete,
}

internal fun interface CredentialStoreCommitObserver {
    fun reached(
        point: CredentialStoreCommitPoint,
        target: Path,
    )
}

internal class FileStalwartCredentialStore(
    private val paths: CredentialStorePaths,
    private val commitObserver: CredentialStoreCommitObserver =
        CredentialStoreCommitObserver { _, _ -> },
) : StalwartCredentialStore {
    @Volatile
    private var closed = false

    override fun load(): CredentialStoreLoadResult {
        checkOpen()
        return try {
            withStableLock {
                cleanupRecognizedTemporaryFiles()
                CredentialStoreLoadResult.Available(readOrInitializeSnapshot())
            }
        } catch (_: Exception) {
            CredentialStoreLoadResult.StoreUnavailable
        }
    }

    override fun replace(
        expectedRevision: Long,
        records: Map<String, StalwartCredentialRecord>,
    ): CredentialStoreWriteResult {
        checkOpen()
        require(expectedRevision >= 0 && expectedRevision != Long.MAX_VALUE) {
            "Expected credential-store revision is invalid"
        }
        validateRecordMap(records)
        return try {
            withStableLock {
                cleanupRecognizedTemporaryFiles()
                val current = readExistingSnapshot()
                try {
                    if (current.revision != expectedRevision) {
                        return@withStableLock CredentialStoreWriteResult.RevisionMismatch(
                            actualRevision = current.revision,
                        )
                    }
                    if (current.revision >= Long.MAX_VALUE - 1) {
                        return@withStableLock CredentialStoreWriteResult.StoreUnavailable
                    }
                    rejectChangedAddresses(current, records)
                    val nextRevision = Math.addExact(current.revision, 1)
                    val keyBytes = readKey()
                    try {
                        val envelope = encrypt(
                            storeId = current.storeId,
                            keyBytes = keyBytes,
                            revision = nextRevision,
                            records = records,
                        )
                        try {
                            writeAtomically(
                                target = paths.ciphertext,
                                bytes = envelope,
                                replaceExisting = true,
                                observeCommit = true,
                            )
                        } finally {
                            envelope.fill(0)
                        }
                    } finally {
                        keyBytes.fill(0)
                    }
                    CredentialStoreWriteResult.Written(nextRevision)
                } finally {
                    current.close()
                }
            }
        } catch (interrupted: CommitInterrupted) {
            throw interrupted.original
        } catch (invalid: StoreInputException) {
            throw invalid
        } catch (_: Exception) {
            CredentialStoreWriteResult.StoreUnavailable
        }
    }

    override fun quarantineUnavailable(): CredentialStoreQuarantineResult {
        checkOpen()
        return try {
            withStableLock {
                cleanupRecognizedTemporaryFiles()
                when (inspectPair()) {
                    StorePair.Absent -> CredentialStoreQuarantineResult.StoreAvailable
                    StorePair.Complete -> {
                        val available = try {
                            readExistingSnapshot()
                        } catch (_: Exception) {
                            null
                        }
                        if (available != null) {
                            available.close()
                            CredentialStoreQuarantineResult.StoreAvailable
                        } else {
                            quarantineExistingPair()
                        }
                    }
                    StorePair.Interrupted -> quarantineExistingPair()
                }
            }
        } catch (partial: PartialQuarantineException) {
            if (partial.published.isEmpty()) {
                CredentialStoreQuarantineResult.StoreUnavailable
            } else {
                CredentialStoreQuarantineResult.PartiallyQuarantined(partial.published)
            }
        } catch (_: Exception) {
            CredentialStoreQuarantineResult.StoreUnavailable
        }
    }

    override fun close() {
        closed = true
    }

    private fun checkOpen() {
        check(!closed) { "Credential store is closed" }
    }

    private fun readOrInitializeSnapshot(): StalwartCredentialSnapshot =
        when (inspectPair()) {
            StorePair.Absent -> {
                initializeEmptyStore()
                readExistingSnapshot()
            }
            StorePair.Complete -> readExistingSnapshot()
            StorePair.Interrupted -> throw StoreUnavailableException()
        }

    private fun readExistingSnapshot(): StalwartCredentialSnapshot {
        if (inspectPair() != StorePair.Complete) throw StoreUnavailableException()
        requireSecureRegularFile(paths.key)
        requireSecureRegularFile(paths.ciphertext)
        val keyBytes = readKey()
        var envelope = ByteArray(0)
        return try {
            envelope = readSecureBytes(paths.ciphertext, MAX_ENVELOPE_BYTES)
            decrypt(keyBytes, envelope)
        } finally {
            keyBytes.fill(0)
            envelope.fill(0)
        }
    }

    private fun initializeEmptyStore() {
        if (inspectPair() != StorePair.Absent) throw StoreUnavailableException()
        val keyBytes = ByteArray(KEY_BYTES).also(secureRandom::nextBytes)
        val storeId = newStoreId()
        var envelope = ByteArray(0)
        try {
            envelope = encrypt(
                storeId = storeId,
                keyBytes = keyBytes,
                revision = 0,
                records = emptyMap(),
            )
            writeAtomically(
                target = paths.key,
                bytes = keyBytes,
                replaceExisting = false,
                observeCommit = false,
            )
            writeAtomically(
                target = paths.ciphertext,
                bytes = envelope,
                replaceExisting = false,
                observeCommit = false,
            )
        } finally {
            keyBytes.fill(0)
            envelope.fill(0)
        }
    }

    private fun readKey(): ByteArray {
        val keyBytes = readSecureBytes(paths.key, KEY_BYTES)
        if (keyBytes.size != KEY_BYTES) {
            keyBytes.fill(0)
            throw StoreUnavailableException()
        }
        return keyBytes
    }

    private fun inspectPair(): StorePair {
        val keyExists = Files.exists(paths.key, LinkOption.NOFOLLOW_LINKS)
        val ciphertextExists = Files.exists(paths.ciphertext, LinkOption.NOFOLLOW_LINKS)
        return when {
            !keyExists && !ciphertextExists -> StorePair.Absent
            keyExists && ciphertextExists -> StorePair.Complete
            else -> StorePair.Interrupted
        }
    }

    private fun rejectChangedAddresses(
        current: StalwartCredentialSnapshot,
        replacement: Map<String, StalwartCredentialRecord>,
    ) {
        current.records.forEach { (accountId, existing) ->
            val updated = replacement[accountId] ?: return@forEach
            if (existing.addressAtCapture != updated.addressAtCapture) {
                throw StoreInputException(
                    "Captured address cannot change without removing the Account record first",
                )
            }
        }
    }

    private fun validateRecordMap(records: Map<String, StalwartCredentialRecord>) {
        require(records.size <= MAX_RECORDS) { "Credential record count is invalid" }
        val ownedSecrets = IdentityHashMap<SecretBytes, Unit>()
        records.forEach { (key, record) ->
            require(key == record.accountId) {
                "Credential record key does not match its immutable Account ID"
            }
            validateString(record.accountId)
            validateString(record.addressAtCapture)
            record.active?.let { generation ->
                claimSecretOwnership(ownedSecrets, generation)
                validateGeneration(generation)
            }
            record.other?.let { generation ->
                claimSecretOwnership(ownedSecrets, generation)
                validateGeneration(generation)
            }
        }
    }

    private fun claimSecretOwnership(
        ownedSecrets: IdentityHashMap<SecretBytes, Unit>,
        generation: CredentialGeneration,
    ) {
        require(!ownedSecrets.containsKey(generation.secret)) {
            "Credential secret ownership is aliased"
        }
        ownedSecrets[generation.secret] = Unit
    }

    private fun validateGeneration(generation: CredentialGeneration) {
        validateString(generation.credentialId)
        validateString(generation.description)
        require(generation.description.startsWith(RESERVED_DESCRIPTION_PREFIX)) {
            "Credential description is outside the reserved namespace"
        }
        generation.secret.read { secret ->
            require(secret.isNotEmpty() && secret.size <= MAX_SECRET_BYTES) {
                "Credential secret length is invalid"
            }
        }
    }

    private fun validateString(value: String) {
        require(value.toByteArray(StandardCharsets.UTF_8).size <= MAX_STRING_BYTES) {
            "Credential text field is too long"
        }
    }

    private fun encrypt(
        storeId: UUID,
        keyBytes: ByteArray,
        revision: Long,
        records: Map<String, StalwartCredentialRecord>,
    ): ByteArray {
        require(revision >= 0) { "Credential-store revision is invalid" }
        validateRecordMap(records)
        val nonce = ByteArray(NONCE_BYTES).also(secureRandom::nextBytes)
        val header = encodeHeader(storeId, nonce)
        val payload = encodePayload(revision, records)
        return try {
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                GCMParameterSpec(GCM_TAG_BITS, nonce),
            )
            cipher.updateAAD(FORMAT_IDENTITY)
            cipher.updateAAD(header)
            val encrypted = cipher.doFinal(payload)
            try {
                ByteBuffer.allocate(Math.addExact(header.size, encrypted.size))
                    .put(header)
                    .put(encrypted)
                    .array()
            } finally {
                encrypted.fill(0)
            }
        } finally {
            nonce.fill(0)
            header.fill(0)
            payload.fill(0)
        }
    }

    private fun decrypt(
        keyBytes: ByteArray,
        envelope: ByteArray,
    ): StalwartCredentialSnapshot {
        if (
            envelope.size < ENVELOPE_HEADER_BYTES + GCM_TAG_BYTES ||
            envelope.size > MAX_ENVELOPE_BYTES
        ) {
            throw StoreUnavailableException()
        }
        val header = envelope.copyOfRange(0, ENVELOPE_HEADER_BYTES)
        val parsedHeader = decodeHeader(header)
        val plaintext = try {
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(keyBytes, "AES"),
                GCMParameterSpec(GCM_TAG_BITS, parsedHeader.nonce),
            )
            cipher.updateAAD(FORMAT_IDENTITY)
            cipher.updateAAD(header)
            cipher.doFinal(
                envelope,
                ENVELOPE_HEADER_BYTES,
                envelope.size - ENVELOPE_HEADER_BYTES,
            )
        } finally {
            header.fill(0)
            parsedHeader.nonce.fill(0)
        }
        return try {
            decodePayload(parsedHeader.storeId, plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    private fun encodeHeader(storeId: UUID, nonce: ByteArray): ByteArray {
        require(storeId != ZERO_UUID) { "Credential store identity is invalid" }
        require(nonce.size == NONCE_BYTES) { "Credential store nonce is invalid" }
        return ByteBuffer.allocate(ENVELOPE_HEADER_BYTES)
            .put(ENVELOPE_MAGIC)
            .put(ENVELOPE_VERSION)
            .putLong(storeId.mostSignificantBits)
            .putLong(storeId.leastSignificantBits)
            .put(nonce)
            .array()
    }

    private fun decodeHeader(header: ByteArray): ParsedHeader {
        if (header.size != ENVELOPE_HEADER_BYTES) throw StoreUnavailableException()
        val buffer = ByteBuffer.wrap(header)
        val magic = ByteArray(ENVELOPE_MAGIC.size)
        buffer.get(magic)
        if (!magic.contentEquals(ENVELOPE_MAGIC)) throw StoreUnavailableException()
        if (buffer.get() != ENVELOPE_VERSION) throw StoreUnavailableException()
        val storeId = UUID(buffer.long, buffer.long)
        if (storeId == ZERO_UUID) throw StoreUnavailableException()
        val nonce = ByteArray(NONCE_BYTES)
        buffer.get(nonce)
        if (buffer.hasRemaining()) throw StoreUnavailableException()
        return ParsedHeader(storeId, nonce)
    }

    private fun encodePayload(
        revision: Long,
        records: Map<String, StalwartCredentialRecord>,
    ): ByteArray {
        val encodedRecords = mutableListOf<EncodedRecord>()
        return try {
            var size = java.lang.Long.BYTES + Integer.BYTES
            records.toSortedMap().values.forEach { source ->
                val record = encodeRecordStrings(source)
                try {
                    size = Math.addExact(size, record.encodedSize())
                    require(size <= MAX_PAYLOAD_BYTES) {
                        "Credential snapshot is too large"
                    }
                    encodedRecords.add(record)
                } catch (failure: Exception) {
                    record.clear()
                    throw failure
                }
            }
            val payload = ByteArray(size)
            try {
                val buffer = ByteBuffer.wrap(payload)
                buffer.putLong(revision)
                buffer.putInt(encodedRecords.size)
                encodedRecords.forEach { record ->
                    putString(buffer, record.accountId)
                    putString(buffer, record.address)
                    buffer.put(phaseCode(record.source.phase))
                    putGeneration(buffer, record.source.active, record.active)
                    putGeneration(buffer, record.source.other, record.other)
                }
                check(!buffer.hasRemaining()) {
                    "Credential snapshot size was inconsistent"
                }
                payload
            } catch (failure: Throwable) {
                payload.fill(0)
                throw failure
            }
        } finally {
            encodedRecords.forEach(EncodedRecord::clear)
        }
    }

    private fun encodeRecordStrings(record: StalwartCredentialRecord): EncodedRecord {
        var accountId = ByteArray(0)
        var address = ByteArray(0)
        var active: EncodedGeneration? = null
        var other: EncodedGeneration? = null
        return try {
            accountId = encodeString(record.accountId)
            address = encodeString(record.addressAtCapture)
            active = record.active?.let(::encodeGenerationStrings)
            other = record.other?.let(::encodeGenerationStrings)
            EncodedRecord(
                source = record,
                accountId = accountId,
                address = address,
                active = active,
                other = other,
            )
        } catch (failure: Exception) {
            accountId.fill(0)
            address.fill(0)
            active?.clear()
            other?.clear()
            throw failure
        }
    }

    private fun encodeGenerationStrings(
        generation: CredentialGeneration,
    ): EncodedGeneration {
        var credentialId = ByteArray(0)
        var description = ByteArray(0)
        return try {
            credentialId = encodeString(generation.credentialId)
            description = encodeString(generation.description)
            EncodedGeneration(
                credentialId = credentialId,
                description = description,
            )
        } catch (failure: Exception) {
            credentialId.fill(0)
            description.fill(0)
            throw failure
        }
    }

    private fun encodeString(value: String): ByteArray =
        value.toByteArray(StandardCharsets.UTF_8).also {
            require(it.size <= MAX_STRING_BYTES) { "Credential text field is too long" }
        }

    private fun putString(buffer: ByteBuffer, encoded: ByteArray) {
        buffer.putInt(encoded.size)
        buffer.put(encoded)
    }

    private fun putGeneration(
        buffer: ByteBuffer,
        generation: CredentialGeneration?,
        encoded: EncodedGeneration?,
    ) {
        if (generation == null) {
            check(encoded == null)
            buffer.put(ABSENT)
            return
        }
        val strings = requireNotNull(encoded)
        buffer.put(PRESENT)
        putString(buffer, strings.credentialId)
        putString(buffer, strings.description)
        buffer.putLong(generation.generation)
        generation.secret.read { secret ->
            buffer.putInt(secret.size)
            buffer.put(secret)
        }
    }

    private fun decodePayload(
        storeId: UUID,
        plaintext: ByteArray,
    ): StalwartCredentialSnapshot {
        if (
            plaintext.size < java.lang.Long.BYTES + Integer.BYTES ||
            plaintext.size > MAX_PAYLOAD_BYTES
        ) {
            throw StoreUnavailableException()
        }
        val buffer = ByteBuffer.wrap(plaintext)
        val revision = buffer.long
        if (revision < 0 || revision == Long.MAX_VALUE) {
            throw StoreUnavailableException()
        }
        val count = buffer.int
        if (count < 0 || count > MAX_RECORDS) throw StoreUnavailableException()
        val records = linkedMapOf<String, StalwartCredentialRecord>()
        try {
            repeat(count) {
                val accountId = readString(buffer)
                val address = readString(buffer)
                val phase = decodePhase(readByte(buffer))
                var active: CredentialGeneration? = null
                var other: CredentialGeneration? = null
                try {
                    active = readGeneration(buffer)
                    other = readGeneration(buffer)
                    val record = StalwartCredentialRecord.takeOwnership(
                        accountId = accountId,
                        addressAtCapture = address,
                        phase = phase,
                        active = active,
                        other = other,
                    )
                    active = null
                    other = null
                    if (records.putIfAbsent(accountId, record) != null) {
                        record.close()
                        throw StoreUnavailableException()
                    }
                } finally {
                    active?.close()
                    other?.close()
                }
            }
            if (buffer.hasRemaining()) throw StoreUnavailableException()
            validateRecordMap(records)
            return StalwartCredentialSnapshot(storeId, revision, records)
        } catch (failure: Throwable) {
            records.values.forEach(StalwartCredentialRecord::close)
            throw failure
        }
    }

    private fun readGeneration(buffer: ByteBuffer): CredentialGeneration? =
        when (readByte(buffer)) {
            ABSENT -> null
            PRESENT -> {
                val credentialId = readString(buffer)
                val description = readString(buffer)
                val generation = readLong(buffer)
                if (generation < 0) throw StoreUnavailableException()
                val secretLength = readLength(buffer, MAX_SECRET_BYTES, allowEmpty = false)
                val secretBytes = ByteArray(secretLength)
                try {
                    requireRemaining(buffer, secretLength)
                    buffer.get(secretBytes)
                    CredentialGeneration(
                        credentialId = credentialId,
                        description = description,
                        generation = generation,
                        secret = SecretBytes.takeOwnership(secretBytes),
                    )
                } catch (failure: Throwable) {
                    secretBytes.fill(0)
                    throw failure
                }
            }
            else -> throw StoreUnavailableException()
        }

    private fun readString(buffer: ByteBuffer): String {
        val length = readLength(buffer, MAX_STRING_BYTES, allowEmpty = false)
        val bytes = ByteArray(length)
        return try {
            requireRemaining(buffer, length)
            buffer.get(bytes)
            UTF8_DECODER.get()
                .reset()
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        } finally {
            bytes.fill(0)
        }
    }

    private fun readLength(
        buffer: ByteBuffer,
        maximum: Int,
        allowEmpty: Boolean,
    ): Int {
        val length = readInt(buffer)
        if (length < 0 || length > maximum || (!allowEmpty && length == 0)) {
            throw StoreUnavailableException()
        }
        requireRemaining(buffer, length)
        return length
    }

    private fun readByte(buffer: ByteBuffer): Byte {
        requireRemaining(buffer, 1)
        return buffer.get()
    }

    private fun readInt(buffer: ByteBuffer): Int {
        requireRemaining(buffer, Integer.BYTES)
        return buffer.int
    }

    private fun readLong(buffer: ByteBuffer): Long {
        requireRemaining(buffer, java.lang.Long.BYTES)
        return buffer.long
    }

    private fun requireRemaining(buffer: ByteBuffer, count: Int) {
        if (count < 0 || buffer.remaining() < count) throw StoreUnavailableException()
    }

    private fun phaseCode(phase: CredentialPhase): Byte = when (phase) {
        CredentialPhase.Active -> 0
        CredentialPhase.Staged -> 1
        CredentialPhase.Retiring -> 2
        CredentialPhase.RemovalPending -> 3
    }

    private fun decodePhase(code: Byte): CredentialPhase = when (code.toInt()) {
        0 -> CredentialPhase.Active
        1 -> CredentialPhase.Staged
        2 -> CredentialPhase.Retiring
        3 -> CredentialPhase.RemovalPending
        else -> throw StoreUnavailableException()
    }

    private fun <T> withStableLock(block: () -> T): T {
        ensureStorageDirectories()
        val processLock = processLocks.computeIfAbsent(paths.lock) { ReentrantLock() }
        return processLock.withLock {
            ensureSecureFile(paths.lock)
            FileChannel.open(
                paths.lock,
                StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS,
            ).use { channel ->
                channel.lock().use {
                    requireSecureRegularFile(paths.lock)
                    block()
                }
            }
        }
    }

    private fun ensureStorageDirectories() {
        requireSafeTrustedRoot()
        ensureSecureDirectory(paths.runtimeRoot)
        ensureSecureDirectory(paths.ciphertext.parent)
        ensureSecureDirectory(paths.key.parent)
    }

    private fun requireSafeTrustedRoot() {
        if (
            Files.isSymbolicLink(paths.trustedRoot) ||
            !Files.isDirectory(paths.trustedRoot, LinkOption.NOFOLLOW_LINKS) ||
            paths.trustedRoot.toRealPath() != paths.trustedRoot
        ) {
            throw StoreUnavailableException()
        }
    }

    private fun ensureSecureDirectory(path: Path) {
        val parent = requireNotNull(path.parent)
        if (
            Files.isSymbolicLink(parent) ||
            !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
        ) {
            throw StoreUnavailableException()
        }
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createDirectory(path)
            } catch (_: FileAlreadyExistsException) {
                // Validate the concurrently created entry below.
            }
        }
        requireSecureDirectory(path)
    }

    private fun requireSecureDirectory(path: Path) {
        if (
            Files.isSymbolicLink(path) ||
            !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
        ) {
            throw StoreUnavailableException()
        }
        if (supportsPosix(path) && Files.getPosixFilePermissions(
                path,
                LinkOption.NOFOLLOW_LINKS,
            ) != DIRECTORY_PERMISSIONS
        ) {
            throw StoreUnavailableException()
        }
    }

    private fun ensureSecureFile(path: Path) {
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            try {
                createFile(path)
            } catch (_: FileAlreadyExistsException) {
                // Validate the concurrently created entry below.
            }
        }
        requireSecureRegularFile(path)
    }

    private fun requireSecureRegularFile(path: Path) {
        if (
            Files.isSymbolicLink(path) ||
            !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        ) {
            throw StoreUnavailableException()
        }
        if (supportsPosix(path) && Files.getPosixFilePermissions(
                path,
                LinkOption.NOFOLLOW_LINKS,
            ) != FILE_PERMISSIONS
        ) {
            throw StoreUnavailableException()
        }
        if (!Files.isReadable(path) || !Files.isWritable(path)) {
            throw StoreUnavailableException()
        }
    }

    private fun createDirectory(path: Path) {
        if (supportsPosix(path.parent)) {
            Files.createDirectory(path, DIRECTORY_ATTRIBUTE)
        } else {
            Files.createDirectory(path)
            path.toFile().setReadable(false, false)
            path.toFile().setWritable(false, false)
            path.toFile().setExecutable(false, false)
            path.toFile().setReadable(true, true)
            path.toFile().setWritable(true, true)
            path.toFile().setExecutable(true, true)
        }
    }

    private fun createFile(path: Path) {
        if (supportsPosix(path.parent)) {
            Files.createFile(path, FILE_ATTRIBUTE)
        } else {
            Files.createFile(path)
            path.toFile().setReadable(false, false)
            path.toFile().setWritable(false, false)
            path.toFile().setExecutable(false, false)
            path.toFile().setReadable(true, true)
            path.toFile().setWritable(true, true)
        }
    }

    private fun writeAtomically(
        target: Path,
        bytes: ByteArray,
        replaceExisting: Boolean,
        observeCommit: Boolean,
    ) {
        val temporary = createUniqueTemporary(target)
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
        if (replaceExisting) {
            if (observeCommit) {
                notifyCommit(CredentialStoreCommitPoint.BeforeReplace, target)
            }
            try {
                Files.move(
                    temporary,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (unsupported: AtomicMoveNotSupportedException) {
                throw StoreUnavailableException(unsupported)
            }
            if (observeCommit) {
                notifyCommit(CredentialStoreCommitPoint.AfterReplace, target)
            }
        } else {
            publishHardLinkWithoutOverwrite(
                source = temporary,
                destination = target,
            )
        }
        fsyncDirectory(target.parent)
        requireSecureRegularFile(target)
    }

    private fun publishHardLinkWithoutOverwrite(
        source: Path,
        destination: Path,
    ) {
        notifyCommit(CredentialStoreCommitPoint.BeforeFailIfExistsPublish, destination)
        Files.createLink(destination, source)
        fsyncDirectory(destination.parent)
        if (!Files.isSameFile(source, destination)) throw StoreUnavailableException()
        requireSecureRegularFile(destination)
        notifyCommit(CredentialStoreCommitPoint.AfterFailIfExistsPublish, destination)
        Files.delete(source)
        fsyncDirectory(source.parent)
    }

    private fun notifyCommit(
        point: CredentialStoreCommitPoint,
        target: Path,
    ) {
        try {
            commitObserver.reached(point, target)
        } catch (failure: RuntimeException) {
            throw CommitInterrupted(failure)
        }
    }

    private fun createUniqueTemporary(target: Path): Path {
        repeat(MAX_NAME_ATTEMPTS) {
            val candidate = target.resolveSibling(
                "${target.fileName}$TEMPORARY_MARKER${UUID.randomUUID()}",
            )
            try {
                createFile(candidate)
                return candidate
            } catch (_: FileAlreadyExistsException) {
                // Generate a different non-overwriting name.
            }
        }
        throw StoreUnavailableException()
    }

    private fun cleanupRecognizedTemporaryFiles() {
        cleanupRecognizedTemporaryFiles(paths.ciphertext)
        cleanupRecognizedTemporaryFiles(paths.key)
    }

    private fun cleanupRecognizedTemporaryFiles(target: Path) {
        val prefix = "${target.fileName}$TEMPORARY_MARKER"
        var deleted = false
        Files.newDirectoryStream(target.parent).use { entries ->
            entries.forEach { candidate ->
                if (isRecognizedTemporaryName(candidate.fileName.toString(), prefix)) {
                    requireSecureRegularFile(candidate)
                    Files.delete(candidate)
                    deleted = true
                }
            }
        }
        if (deleted) fsyncDirectory(target.parent)
    }

    private fun isRecognizedTemporaryName(name: String, prefix: String): Boolean {
        if (!name.startsWith(prefix)) return false
        val suffix = name.removePrefix(prefix)
        if (suffix.length != UUID_TEXT_LENGTH) return false
        return try {
            UUID.fromString(suffix).toString() == suffix
        } catch (_: IllegalArgumentException) {
            false
        }
    }

    private fun readSecureBytes(path: Path, maximumSize: Int): ByteArray {
        requireSecureRegularFile(path)
        val before = Files.readAttributes(
            path,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )
        if (before.size() < 0 || before.size() > maximumSize) {
            throw StoreUnavailableException()
        }
        val bytes = ByteArray(before.size().toInt())
        try {
            FileChannel.open(
                path,
                StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS,
            ).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) {
                    if (channel.read(buffer) < 0) throw EOFException()
                }
                val trailing = ByteArray(1)
                try {
                    if (channel.read(ByteBuffer.wrap(trailing)) >= 0) {
                        throw StoreUnavailableException()
                    }
                } finally {
                    trailing.fill(0)
                }
            }
            val after = Files.readAttributes(
                path,
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            )
            if (
                !after.isRegularFile ||
                before.fileKey() != after.fileKey() ||
                before.size() != after.size() ||
                before.lastModifiedTime() != after.lastModifiedTime()
            ) {
                throw StoreUnavailableException()
            }
            return bytes
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    private fun quarantineExistingPair(): CredentialStoreQuarantineResult {
        val sources = listOf(paths.key, paths.ciphertext)
            .filter { Files.exists(it, LinkOption.NOFOLLOW_LINKS) }
        if (sources.isEmpty()) return CredentialStoreQuarantineResult.StoreAvailable
        sources.forEach(::requireQuarantinableRegularFile)
        ensureSecureDirectory(paths.quarantine)

        val quarantineId = UUID.randomUUID()
        val destinations = sources.associateWith { source ->
            paths.quarantine.resolve(
                "${source.fileName}.quarantined-$quarantineId",
            )
        }
        val published = mutableListOf<Path>()
        try {
            destinations.forEach { (source, destination) ->
                notifyCommit(
                    CredentialStoreCommitPoint.BeforeFailIfExistsPublish,
                    destination,
                )
                Files.createLink(destination, source)
                published.add(destination)
                fsyncDirectory(paths.quarantine)
                if (!Files.isSameFile(source, destination)) {
                    throw StoreUnavailableException()
                }
                setOwnerOnlyFile(destination)
                requireSecureRegularFile(destination)
                notifyCommit(
                    CredentialStoreCommitPoint.AfterFailIfExistsPublish,
                    destination,
                )
                Files.delete(source)
                fsyncDirectory(source.parent)
                notifyCommit(
                    CredentialStoreCommitPoint.AfterQuarantineSourceDelete,
                    destination,
                )
            }
        } catch (failure: Exception) {
            throw PartialQuarantineException(published.toList(), failure)
        }
        return CredentialStoreQuarantineResult.Quarantined(published)
    }

    private fun requireQuarantinableRegularFile(path: Path) {
        if (
            Files.isSymbolicLink(path) ||
            !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        ) {
            throw StoreUnavailableException()
        }
    }

    private fun setOwnerOnlyFile(path: Path) {
        if (supportsPosix(path)) {
            Files.setPosixFilePermissions(path, FILE_PERMISSIONS)
        } else {
            path.toFile().setReadable(false, false)
            path.toFile().setWritable(false, false)
            path.toFile().setExecutable(false, false)
            path.toFile().setReadable(true, true)
            path.toFile().setWritable(true, true)
        }
    }

    private fun fsyncDirectory(directory: Path) {
        try {
            FileChannel.open(directory, StandardOpenOption.READ).use { it.force(true) }
        } catch (_: UnsupportedOperationException) {
            // Directory fsync is not available on every JDK filesystem provider.
        } catch (_: AccessDeniedException) {
            if (isWindows()) return
            throw StoreUnavailableException()
        }
    }

    private fun supportsPosix(path: Path): Boolean =
        path.fileSystem.supportedFileAttributeViews().contains("posix")

    private fun isWindows(): Boolean =
        System.getProperty("os.name").startsWith("Windows", ignoreCase = true)

    private fun newStoreId(): UUID {
        var storeId = UUID.randomUUID()
        while (storeId == ZERO_UUID) storeId = UUID.randomUUID()
        return storeId
    }

    private data class ParsedHeader(
        val storeId: UUID,
        val nonce: ByteArray,
    )

    private data class EncodedGeneration(
        val credentialId: ByteArray,
        val description: ByteArray,
    ) {
        fun encodedSize(): Int =
            Integer.BYTES + credentialId.size +
                Integer.BYTES + description.size +
                java.lang.Long.BYTES +
                Integer.BYTES

        fun clear() {
            credentialId.fill(0)
            description.fill(0)
        }
    }

    private data class EncodedRecord(
        val source: StalwartCredentialRecord,
        val accountId: ByteArray,
        val address: ByteArray,
        val active: EncodedGeneration?,
        val other: EncodedGeneration?,
    ) {
        fun encodedSize(): Int {
            var size = Integer.BYTES + accountId.size +
                Integer.BYTES + address.size +
                1 +
                1 +
                1
            source.active?.secret?.read { secret ->
                size = Math.addExact(size, requireNotNull(active).encodedSize())
                size = Math.addExact(size, secret.size)
            }
            source.other?.secret?.read { secret ->
                size = Math.addExact(size, requireNotNull(other).encodedSize())
                size = Math.addExact(size, secret.size)
            }
            return size
        }

        fun clear() {
            accountId.fill(0)
            address.fill(0)
            active?.clear()
            other?.clear()
        }
    }

    private enum class StorePair {
        Absent,
        Complete,
        Interrupted,
    }

    private class StoreUnavailableException(
        cause: Throwable? = null,
    ) : IOException("Credential store is unavailable", cause)

    private class StoreInputException(
        message: String,
    ) : IllegalArgumentException(message)

    private class CommitInterrupted(
        val original: RuntimeException,
    ) : RuntimeException("Credential snapshot commit was interrupted")

    private class PartialQuarantineException(
        val published: List<Path>,
        cause: Throwable,
    ) : IOException("Credential quarantine was interrupted", cause)

    companion object {
        private val secureRandom = SecureRandom()
        private val processLocks = ConcurrentHashMap<Path, ReentrantLock>()
        private val ZERO_UUID = UUID(0, 0)
        private val ENVELOPE_MAGIC = "MSSTCRD1".toByteArray(StandardCharsets.US_ASCII)
        private const val ENVELOPE_VERSION: Byte = 1
        private const val NONCE_BYTES = 12
        private const val ENVELOPE_HEADER_BYTES = 8 + 1 + 16 + NONCE_BYTES
        private const val KEY_BYTES = 32
        private const val GCM_TAG_BITS = 128
        private const val GCM_TAG_BYTES = GCM_TAG_BITS / 8
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        private val FORMAT_IDENTITY =
            "mail-sandbox/stalwart-app-passwords-envelope/v1"
                .toByteArray(StandardCharsets.US_ASCII)
        private const val RESERVED_DESCRIPTION_PREFIX = "mail-sandbox/debug-dashboard/"
        private const val MAX_RECORDS = 10_000
        private const val MAX_STRING_BYTES = 1 shl 20
        private const val MAX_SECRET_BYTES = 1 shl 20
        private const val MAX_PAYLOAD_BYTES = 16 shl 20
        private const val MAX_ENVELOPE_BYTES =
            ENVELOPE_HEADER_BYTES + MAX_PAYLOAD_BYTES + GCM_TAG_BYTES
        private const val MAX_NAME_ATTEMPTS = 16
        private const val UUID_TEXT_LENGTH = 36
        private const val TEMPORARY_MARKER = ".tmp-"
        private const val ABSENT: Byte = 0
        private const val PRESENT: Byte = 1
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
