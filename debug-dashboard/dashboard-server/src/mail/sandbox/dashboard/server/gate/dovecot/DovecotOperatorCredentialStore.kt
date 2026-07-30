package mail.sandbox.dashboard.server.gate.dovecot

import java.io.PrintStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.UserPrincipal
import java.security.SecureRandom
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
    val rotationIntent: Path,
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
                rotationIntent ==
                secretsDirectory.resolve("dovecot-operator-rotation") &&
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
                rotationIntent =
                    secretsDirectory.resolve("dovecot-operator-rotation"),
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
    BeforeIntentReplace,
    AfterIntentReplace,
    BeforeMasterReplace,
    AfterMasterReplace,
    BeforeActiveReplace,
    AfterActiveReplace,
    StagedAccepted,
    ApplicationVerified,
    DrainCompleted,
    OldRejected,
    NewVerified,
    RollbackStagedRejected,
    RollbackOldVerified,
    BeforeSlotDelete,
    AfterSlotDelete,
    BeforeIntentDelete,
    AfterIntentDelete,
    BeforeTemporaryDelete,
    AfterTemporaryDelete,
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

internal interface DovecotOperatorRotationRuntime {
    fun observePasswdFile(
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
    ): DovecotOperatorProbeResult

    fun activateApplication(credential: DovecotOperatorCredential)

    fun verifyApplication(
        target: DovecotOperatorTarget,
        expectedId: DovecotOperatorId,
    ): DovecotOperatorProbeResult

    fun blockAndDrain(id: DovecotOperatorId)
}

internal fun interface DovecotOperatorRotationSleeper {
    fun sleep(milliseconds: Long)
}

internal class DovecotOperatorCredentialStore(
    private val paths: DovecotOperatorPaths,
    private val hasher: DovecotOperatorHashBoundary,
    private val verifier: DovecotOperatorHashVerifier,
    private val generator: DovecotOperatorSecretGenerator =
        SecureDovecotOperatorSecretGenerator(),
    private val observer: DovecotOperatorStoreObserver =
        DovecotOperatorStoreObserver { _, _ -> },
    private val rotationSleeper: DovecotOperatorRotationSleeper =
        DovecotOperatorRotationSleeper(Thread::sleep),
) : DovecotOperatorBootstrapper {
    private val durableRepository =
        DovecotOperatorDurableRepository(paths, observer)

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

    fun rotateOrRecover(
        target: DovecotOperatorTarget,
        runtime: DovecotOperatorRotationRuntime,
    ): DovecotOperatorId = withStableLock {
        if (durableRepository.fixedPathExists(paths.rotationIntent)) {
            return@withStableLock recoverRotationLocked(target, runtime)
        }
        val current = when (val state = readState()) {
            OperatorState.Empty ->
                throw IllegalStateException("Dovecot operator credential is absent")
            is OperatorState.Consistent -> state
        }
        val old = current.id
        val new = old.other()
        current.secret.fill(0)
        val oldMaster = readMaster()
        operatorSafetyCheck(oldMaster.id == old) {
            "Dovecot operator master and active reference disagree"
        }

        lateinit var stagedHash: String
        generator.generate().use { staged ->
            requireDifferentSecret(staged, old)
            stagedHash = hash(staged)
            writeAsciiAtomic(
                target = paths.rotationIntent,
                value = "${old.reference}:${new.reference}",
                before = DovecotOperatorCommitPoint.BeforeIntentReplace,
                after = DovecotOperatorCommitPoint.AfterIntentReplace,
            )
            staged.withBytes { bytes ->
                durableRepository.writeAtomic(
                    target = paths.slot(new),
                    contents = bytes,
                    before = DovecotOperatorCommitPoint.BeforeSlotReplace,
                    after = DovecotOperatorCommitPoint.AfterSlotReplace,
                )
            }
            writeMaster(
                listOf(
                    DovecotOperatorMaster(old, oldMaster.hash),
                    DovecotOperatorMaster(new, stagedHash),
                ),
            )

            awaitProbeOutcome(
                target = target,
                id = new,
                expected = DovecotOperatorProbeResult.Success,
                operation = runtime::observePasswdFile,
                failureMessage =
                    "Staged Dovecot operator credential was not observed",
            )
            observer.reached(
                DovecotOperatorCommitPoint.StagedAccepted,
                paths.masterUsers,
            )

            writeAsciiAtomic(
                target = paths.active,
                value = new.reference,
                before = DovecotOperatorCommitPoint.BeforeActiveReplace,
                after = DovecotOperatorCommitPoint.AfterActiveReplace,
            )
            loadCredential(new).use { credential ->
                runInterruptibly {
                    runtime.activateApplication(credential)
                }
            }
            awaitRuntimeOutcome(
                expected = DovecotOperatorProbeResult.Success,
                resultSupplier = {
                    runtime.verifyApplication(target, new)
                },
                failureMessage =
                    "New Dovecot operator application generation was not verified",
            )
            observer.reached(
                DovecotOperatorCommitPoint.ApplicationVerified,
                paths.active,
            )

            runInterruptibly { runtime.blockAndDrain(old) }
            observer.reached(
                DovecotOperatorCommitPoint.DrainCompleted,
                paths.slot(old),
            )
            writeMaster(listOf(DovecotOperatorMaster(new, stagedHash)))

            awaitProbeOutcome(
                target = target,
                id = old,
                expected = DovecotOperatorProbeResult.AuthenticationFailure,
                operation = runtime::observePasswdFile,
                failureMessage =
                    "Revoked Dovecot operator credential remained accepted",
            )
            observer.reached(
                DovecotOperatorCommitPoint.OldRejected,
                paths.masterUsers,
            )
            awaitProbeOutcome(
                target = target,
                id = new,
                expected = DovecotOperatorProbeResult.Success,
                operation = runtime::observePasswdFile,
                failureMessage =
                    "Active Dovecot operator credential was not accepted",
            )
            observer.reached(
                DovecotOperatorCommitPoint.NewVerified,
                paths.masterUsers,
            )
        }

        durableRepository.deleteDurably(
            target = paths.slot(old),
            before = DovecotOperatorCommitPoint.BeforeSlotDelete,
            after = DovecotOperatorCommitPoint.AfterSlotDelete,
        )
        requireFinalProjectionWithIntent(
            intent = DovecotOperatorRotationIntent(old, new),
            id = new,
            hash = stagedHash,
        )
        finishRecoveredRotation(new)
        new
    }

    fun recoverRotation(
        target: DovecotOperatorTarget,
        runtime: DovecotOperatorRotationRuntime,
    ): DovecotOperatorId = withStableLock(recoverTemporaries = true) {
        if (durableRepository.fixedPathExists(paths.rotationIntent)) {
            recoverRotationLocked(target, runtime)
        } else {
            when (val state = readState()) {
                OperatorState.Empty ->
                    throw IllegalStateException(
                        "Dovecot operator credential is absent",
                    )
                is OperatorState.Consistent -> {
                    state.secret.fill(0)
                    state.id
                }
            }
        }
    }

    private fun recoverRotationLocked(
        target: DovecotOperatorTarget,
        runtime: DovecotOperatorRotationRuntime,
    ): DovecotOperatorId {
        val intent = readRotationIntent()
        val active = readActiveReference()
        val masters = readMasters()
        val rawSlots = DovecotOperatorId.entries.filterTo(mutableSetOf()) { id ->
            durableRepository.fixedPathExists(paths.slot(id))
        }
        when (
            val phase = DovecotOperatorRotationProjection(
                intent = intent,
                active = active,
                masterIds = masters.map { it.id },
                rawSlots = rawSlots,
            ).phase()
        ) {
            is DovecotOperatorRotationPhase.Rollback -> {
                requirePreSwitchProjection(intent, masters)
                val oldMaster = masters.single { it.id == intent.old }
                if (masters.size == 2) {
                    writeMaster(listOf(oldMaster))
                }
                if (phase.stagedRawPresent) {
                    awaitProbeOutcome(
                        target = target,
                        id = intent.new,
                        expected =
                            DovecotOperatorProbeResult.AuthenticationFailure,
                        operation = runtime::observePasswdFile,
                        failureMessage =
                            "Rolled-back Dovecot operator credential " +
                                "remained accepted",
                    )
                    observer.reached(
                        DovecotOperatorCommitPoint.RollbackStagedRejected,
                        paths.masterUsers,
                    )
                    awaitProbeOutcome(
                        target = target,
                        id = intent.old,
                        expected = DovecotOperatorProbeResult.Success,
                        operation = runtime::observePasswdFile,
                        failureMessage =
                            "Restored Dovecot operator credential " +
                                "was not accepted",
                    )
                    observer.reached(
                        DovecotOperatorCommitPoint.RollbackOldVerified,
                        paths.masterUsers,
                    )
                    durableRepository.deleteDurably(
                        target = paths.slot(intent.new),
                        before = DovecotOperatorCommitPoint.BeforeSlotDelete,
                        after = DovecotOperatorCommitPoint.AfterSlotDelete,
                    )
                }
                requireFinalProjectionWithIntent(
                    intent = intent,
                    id = intent.old,
                    hash = oldMaster.hash,
                )
                finishRecoveredRotation(intent.old)
                return intent.old
            }

            is DovecotOperatorRotationPhase.Forward -> {
                requirePostSwitchProjection(intent, masters)
                val newMaster = masters.single { it.id == intent.new }
                loadCredential(intent.new).use { credential ->
                    runInterruptibly {
                        runtime.activateApplication(credential)
                    }
                }
                awaitRuntimeOutcome(
                    expected = DovecotOperatorProbeResult.Success,
                    resultSupplier = {
                        runtime.verifyApplication(target, intent.new)
                    },
                    failureMessage =
                        "New Dovecot operator application generation " +
                            "was not verified",
                )
                observer.reached(
                    DovecotOperatorCommitPoint.ApplicationVerified,
                    paths.active,
                )
                runInterruptibly { runtime.blockAndDrain(intent.old) }
                observer.reached(
                    DovecotOperatorCommitPoint.DrainCompleted,
                    paths.slot(intent.old),
                )
                if (masters.size == 2) {
                    writeMaster(listOf(newMaster))
                }
                if (phase.oldRawPresent) {
                    awaitProbeOutcome(
                        target = target,
                        id = intent.old,
                        expected =
                            DovecotOperatorProbeResult.AuthenticationFailure,
                        operation = runtime::observePasswdFile,
                        failureMessage =
                            "Revoked Dovecot operator credential " +
                                "remained accepted",
                    )
                    observer.reached(
                        DovecotOperatorCommitPoint.OldRejected,
                        paths.masterUsers,
                    )
                }
                awaitProbeOutcome(
                    target = target,
                    id = intent.new,
                    expected = DovecotOperatorProbeResult.Success,
                    operation = runtime::observePasswdFile,
                    failureMessage =
                        "Active Dovecot operator credential was not accepted",
                )
                observer.reached(
                    DovecotOperatorCommitPoint.NewVerified,
                    paths.masterUsers,
                )
                if (phase.oldRawPresent) {
                    durableRepository.deleteDurably(
                        target = paths.slot(intent.old),
                        before = DovecotOperatorCommitPoint.BeforeSlotDelete,
                        after = DovecotOperatorCommitPoint.AfterSlotDelete,
                    )
                }
                requireFinalProjectionWithIntent(
                    intent = intent,
                    id = intent.new,
                    hash = newMaster.hash,
                )
                finishRecoveredRotation(intent.new)
                return intent.new
            }
        }
    }

    private fun finishRecoveredRotation(id: DovecotOperatorId) {
        durableRepository.deleteDurably(
            target = paths.rotationIntent,
            before = DovecotOperatorCommitPoint.BeforeIntentDelete,
            after = DovecotOperatorCommitPoint.AfterIntentDelete,
        )
        val final = when (val state = readState()) {
            OperatorState.Empty ->
                throw IllegalStateException(
                    "Dovecot operator rotation verification failed",
                )
            is OperatorState.Consistent -> state
        }
        try {
            operatorSafetyCheck(final.id == id) {
                "Dovecot operator rotation verification failed"
            }
        } finally {
            final.secret.fill(0)
        }
        observer.reached(
            DovecotOperatorCommitPoint.FinalVerified,
            paths.active,
        )
    }

    private fun requirePreSwitchProjection(
        intent: DovecotOperatorRotationIntent,
        masters: List<DovecotOperatorMaster>,
    ) {
        masters.forEach(::verifyMaster)
        if (
            durableRepository.fixedPathExists(paths.slot(intent.new)) &&
            masters.none { it.id == intent.new }
        ) {
            requireValidRawSlot(intent.new)
        }
        if (durableRepository.fixedPathExists(paths.slot(intent.new))) {
            requireDistinctRawSlots(intent.old, intent.new)
        }
    }

    private fun requirePostSwitchProjection(
        intent: DovecotOperatorRotationIntent,
        masters: List<DovecotOperatorMaster>,
    ) {
        masters.forEach(::verifyMaster)
        if (
            durableRepository.fixedPathExists(paths.slot(intent.old)) &&
            masters.none { it.id == intent.old }
        ) {
            requireValidRawSlot(intent.old)
        }
        if (durableRepository.fixedPathExists(paths.slot(intent.old))) {
            requireDistinctRawSlots(intent.old, intent.new)
        }
    }

    private fun requireFinalProjectionWithIntent(
        intent: DovecotOperatorRotationIntent,
        id: DovecotOperatorId,
        hash: String,
    ) {
        operatorSafetyCheck(
            readRotationIntent() == intent &&
                readActiveReference() == id &&
                durableRepository.fixedPathExists(paths.slot(id)) &&
                !durableRepository.fixedPathExists(paths.slot(id.other())),
        ) {
            "Dovecot operator recovered projection is invalid"
        }
        val masters = readMasters()
        operatorSafetyCheck(
            masters.size == 1 &&
                masters.single().id == id &&
                masters.single().hash == hash,
        ) {
            "Dovecot operator recovered projection is invalid"
        }
        verifyMaster(masters.single())
    }

    private fun verifyMaster(master: DovecotOperatorMaster) {
        val bytes = durableRepository.readSlot(master.id)
        try {
            DovecotOperatorSecret.requireValid(bytes)
            val verified = DovecotOperatorSecret
                .takeOwnership(bytes)
                .use { verifier.verify(it, master.hash) }
            operatorSafetyCheck(verified) {
                "Dovecot operator secret and master hash disagree"
            }
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    private fun requireValidRawSlot(id: DovecotOperatorId) {
        val bytes = durableRepository.readSlot(id)
        try {
            DovecotOperatorSecret.requireValid(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun requireDistinctRawSlots(
        first: DovecotOperatorId,
        second: DovecotOperatorId,
    ) = DovecotOperatorRawSlotPair.requireDistinct(
        readFirst = {
            durableRepository.readSlot(first)
        },
        readSecond = {
            durableRepository.readSlot(second)
        },
    )

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
                durableRepository.writeAtomic(
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
                durableRepository.writeAtomic(
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
                durableRepository.writeAtomic(
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

    private fun <T> withStableLock(
        recoverTemporaries: Boolean = false,
        block: () -> T,
    ): T = durableRepository.withStableLock(recoverTemporaries, block)

    private fun readState(): OperatorState {
        durableRepository.requireNoTemporaryState()
        operatorSafetyCheck(
            !durableRepository.fixedPathExists(paths.rotationIntent),
        ) {
            "Dovecot operator rotation requires explicit recovery"
        }
        val slotAExists = durableRepository.fixedPathExists(paths.slotA)
        val slotBExists = durableRepository.fixedPathExists(paths.slotB)
        val activeExists = durableRepository.fixedPathExists(paths.active)
        val masterExists = durableRepository.fixedPathExists(paths.masterUsers)
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

        val activeBytes = durableRepository.readActiveReference()
        val id = try {
            val reference = decodeAscii(activeBytes, "active reference")
            DovecotOperatorId.fromReference(reference)
        } finally {
            activeBytes.fill(0)
        }
        operatorSafetyCheck(
            durableRepository.fixedPathExists(paths.slot(id)) &&
                !durableRepository.fixedPathExists(paths.slot(id.other())),
        ) {
            "Dovecot operator credential state is inconsistent"
        }

        val secret = durableRepository.readSlot(id)
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

    private fun readMaster(): DovecotOperatorMaster {
        val masters = readMasters()
        operatorSafetyCheck(masters.size == 1) {
            "Dovecot operator master file is invalid"
        }
        return masters.single()
    }

    private fun readMasters(): List<DovecotOperatorMaster> {
        val bytes = durableRepository.readMasterUsers()
        return try {
            operatorSafetyCheck(
                bytes.isNotEmpty() &&
                    bytes.last() == '\n'.code.toByte() &&
                    bytes.count { it == '\n'.code.toByte() } in 1..2 &&
                    bytes.none { it == '\r'.code.toByte() },
            ) {
                "Dovecot operator master file is invalid"
            }
            val textBytes = bytes.copyOf(bytes.size - 1)
            try {
                val entries = decodeAscii(
                    textBytes,
                    "master file",
                ).split('\n').map(::parseMasterLine)
                operatorSafetyCheck(
                    entries.map { it.id }.distinct().size == entries.size,
                ) {
                    "Dovecot operator master file is invalid"
                }
                entries
            } finally {
                textBytes.fill(0)
            }
        } finally {
            bytes.fill(0)
        }
    }

    private fun parseMasterLine(line: String): DovecotOperatorMaster {
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
        return DovecotOperatorMaster(id, hash)
    }

    private fun readRotationIntent(): DovecotOperatorRotationIntent {
        val bytes = durableRepository.readRotationIntent()
        return try {
            operatorSafetyCheck(
                bytes.size == MAX_ROTATION_INTENT_BYTES &&
                    bytes[1] == ':'.code.toByte(),
            ) {
                "Dovecot operator rotation intent is invalid"
            }
            val old = DovecotOperatorId.fromReference(
                decodeAscii(byteArrayOf(bytes[0]), "rotation intent"),
            )
            val new = DovecotOperatorId.fromReference(
                decodeAscii(byteArrayOf(bytes[2]), "rotation intent"),
            )
            operatorSafetyCheck(old != new && old.other() == new) {
                "Dovecot operator rotation intent is invalid"
            }
            DovecotOperatorRotationIntent(old, new)
        } finally {
            bytes.fill(0)
        }
    }

    private fun readActiveReference(): DovecotOperatorId {
        val bytes = durableRepository.readActiveReference()
        return try {
            DovecotOperatorId.fromReference(
                decodeAscii(bytes, "active reference"),
            )
        } finally {
            bytes.fill(0)
        }
    }

    private fun hash(secret: DovecotOperatorSecret): String = try {
        hasher.hash(secret).also(EligibilityEntry::requireValidHash)
    } catch (failure: IllegalArgumentException) {
        throw IllegalStateException(
            "Dovecot operator password hashing returned an invalid result",
            failure,
        )
    }

    private fun requireDifferentSecret(
        staged: DovecotOperatorSecret,
        old: DovecotOperatorId,
    ) {
        val oldBytes = durableRepository.readSlot(old)
        try {
            operatorSafetyCheck(
                !staged.withBytes(oldBytes::contentEquals),
            ) {
                "Dovecot operator rotation generated a repeated credential"
            }
        } finally {
            oldBytes.fill(0)
        }
    }

    private fun writeMaster(entries: List<DovecotOperatorMaster>) {
        operatorSafetyCheck(
            entries.size in 1..2 &&
                entries.map { it.id }.distinct().size == entries.size,
        ) {
            "Dovecot operator master state is invalid"
        }
        val contents = entries.joinToString(
            separator = "",
        ) { entry ->
            EligibilityEntry.requireValidHash(entry.hash)
            "${entry.id.masterUsername}:${entry.hash}\n"
        }.toByteArray(StandardCharsets.US_ASCII)
        try {
            durableRepository.writeAtomic(
                target = paths.masterUsers,
                contents = contents,
                before = DovecotOperatorCommitPoint.BeforeMasterReplace,
                after = DovecotOperatorCommitPoint.AfterMasterReplace,
            )
        } finally {
            contents.fill(0)
        }
    }

    private fun writeAsciiAtomic(
        target: Path,
        value: String,
        before: DovecotOperatorCommitPoint,
        after: DovecotOperatorCommitPoint,
    ) {
        val contents = value.toByteArray(StandardCharsets.US_ASCII)
        try {
            durableRepository.writeAtomic(target, contents, before, after)
        } finally {
            contents.fill(0)
        }
    }

    private fun awaitProbeOutcome(
        target: DovecotOperatorTarget,
        id: DovecotOperatorId,
        expected: DovecotOperatorProbeResult,
        operation: (
            DovecotOperatorTarget,
            DovecotOperatorCredential,
        ) -> DovecotOperatorProbeResult,
        failureMessage: String,
    ) {
        awaitRuntimeOutcome(
            expected = expected,
            resultSupplier = {
                loadCredential(id).use { credential ->
                    operation(target, credential)
                }
            },
            failureMessage = failureMessage,
        )
    }

    private fun awaitRuntimeOutcome(
        expected: DovecotOperatorProbeResult,
        resultSupplier: () -> DovecotOperatorProbeResult,
        failureMessage: String,
    ) {
        repeat(ROTATION_OBSERVATION_ATTEMPTS) { attempt ->
            val result = runInterruptibly(resultSupplier)
            when {
                result == expected -> return
                expected == DovecotOperatorProbeResult.Success &&
                    result == DovecotOperatorProbeResult.AuthenticationFailure ->
                    Unit
                expected == DovecotOperatorProbeResult.AuthenticationFailure &&
                    result == DovecotOperatorProbeResult.Success ->
                    Unit
                result == DovecotOperatorProbeResult.ProtocolFailure ->
                    throw IllegalStateException(
                        "$failureMessage at the protocol boundary",
                    )
                result == DovecotOperatorProbeResult.TransportFailure ->
                    throw IllegalStateException(
                        "$failureMessage at the transport boundary",
                    )
                else -> throw IllegalStateException(failureMessage)
            }
            if (attempt + 1 == ROTATION_OBSERVATION_ATTEMPTS) {
                throw IllegalStateException(failureMessage)
            }
            try {
                rotationSleeper.sleep(ROTATION_OBSERVATION_DELAY_MILLIS)
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt()
                throw interrupted
            }
        }
    }

    private fun <T> runInterruptibly(block: () -> T): T {
        if (Thread.currentThread().isInterrupted) {
            throw InterruptedException(
                "Dovecot operator rotation was interrupted",
            )
        }
        val result = try {
            block()
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw interrupted
        }
        if (Thread.currentThread().isInterrupted) {
            throw InterruptedException(
                "Dovecot operator rotation was interrupted",
            )
        }
        return result
    }

    private fun loadCredential(id: DovecotOperatorId): DovecotOperatorCredential {
        val bytes = durableRepository.readSlot(id)
        try {
            DovecotOperatorSecret.requireValid(bytes)
            return DovecotOperatorCredential(
                id,
                DovecotOperatorSecret.takeOwnership(bytes),
            )
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
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

    companion object {
        private const val MAX_ROTATION_INTENT_BYTES = 3
        private const val ROTATION_OBSERVATION_ATTEMPTS = 7
        private const val ROTATION_OBSERVATION_DELAY_MILLIS = 250L
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
