package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.security.MessageDigest
import java.util.concurrent.locks.ReentrantLock
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.withLock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

internal fun interface StalwartDurableCredentialPhaseObserver {
    fun persisted(
        accountId: String,
        phase: CredentialPhase,
    )
}

internal class StalwartMailAccessService(
    private val store: StalwartCredentialStore,
    private val management: StalwartCredentialManagementRemote,
    private val owner: StalwartCredentialOwnerRemote,
    private val probe: StalwartMailCredentialProbeRemote,
    private val leases: StalwartCredentialLeaseRegistry,
    protectedAccountIds: Set<String>,
    private val durablePhaseObserver: StalwartDurableCredentialPhaseObserver =
        StalwartDurableCredentialPhaseObserver { _, _ -> },
    private val definitiveCreatedCleanupTimeout: Duration = 30.seconds,
) {
    private val protectedAccountIds = protectedAccountIds.toSet()
    private val storeWriteLock = ReentrantLock()

    init {
        require(this.protectedAccountIds.none(String::isBlank)) {
            "Protected Stalwart Account ID is absent"
        }
        require(
            definitiveCreatedCleanupTimeout > Duration.ZERO &&
                definitiveCreatedCleanupTimeout <= 30.seconds
        ) {
            "Definitive Created cleanup timeout is invalid"
        }
    }

    suspend fun project(
        account: StalwartMailAccount,
    ): StalwartMailAccessProjection {
        val loaded = store.load()
        if (loaded !is CredentialStoreLoadResult.Available) {
            return projection(account, StalwartMailAccessState.StoreUnavailable)
        }
        loaded.snapshot.use { snapshot ->
            val record = snapshot.records[account.accountId]
            if (account.accountId in protectedAccountIds) {
                val state = if (record == null) {
                    StalwartMailAccessState.EnrollmentRequired
                } else {
                    StalwartMailAccessState.RecoveryRequired
                }
                return projection(account, state)
            }
            if (record != null && record.addressAtCapture != account.address) {
                return projection(account, StalwartMailAccessState.RecoveryRequired)
            }
            val inventory = when (
                val remote = management.inventory(account.accountId)
            ) {
                is StalwartRemoteRead.Available -> remote.value
                StalwartRemoteRead.Unavailable ->
                    return projection(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                    )
            }
            if (inventory.accountId != account.accountId) {
                return projection(account, StalwartMailAccessState.RecoveryRequired)
            }
            return projectAvailable(
                account = account,
                snapshot = snapshot,
                record = record,
                inventory = inventory,
            )
        }
    }

    /**
     * This operation acquires the shared permit before loading the active
     * generation. It never accepts a caller-supplied Ready projection.
     */
    suspend fun acquireMailLease(
        account: StalwartMailAccount,
    ): StalwartMailLeaseAcquireResult {
        if (account.accountId in protectedAccountIds) {
            return StalwartMailLeaseAcquireResult.Unavailable(
                StalwartMailLeaseUnavailableReason.NotReady,
            )
        }
        return leases.acquireMail(account.accountId) {
            loadReadyMaterial(account)
        }
    }

    suspend fun enroll(
        account: StalwartMailAccount,
        normalPassword: StalwartNormalPassword,
    ): StalwartMailAccessResult {
        try {
            if (account.accountId in protectedAccountIds) {
                return StalwartMailAccessResult.ReconciliationRequired(
                    projection(
                        account,
                        StalwartMailAccessState.EnrollmentRequired,
                    ),
                    StalwartMailAccessReason.ProtectedIdentity,
                )
            }
            return when (
                val exclusive = leases.acquireExclusive(account.accountId)
            ) {
                is StalwartExclusiveLeaseAcquireResult.Acquired ->
                    exclusive.lease.use {
                        enrollExclusive(account, normalPassword)
                    }
                StalwartExclusiveLeaseAcquireResult.TimedOut ->
                    StalwartMailAccessResult.RetryableFailure(
                    projection(
                        account,
                        currentLocalStateOrRecovery(account),
                    ),
                    StalwartMailAccessReason.LeaseDrainTimedOut,
                )
            }
        } finally {
            normalPassword.close()
        }
    }

    suspend fun repair(
        account: StalwartMailAccount,
        normalPassword: StalwartNormalPassword,
    ): StalwartMailAccessResult {
        try {
            if (account.accountId in protectedAccountIds) {
                return StalwartMailAccessResult.ReconciliationRequired(
                    projection(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                    ),
                    StalwartMailAccessReason.ProtectedIdentity,
                )
            }
            return when (
                val exclusive = leases.acquireExclusive(account.accountId)
            ) {
                is StalwartExclusiveLeaseAcquireResult.Acquired ->
                    exclusive.lease.use {
                        repairExclusive(account, normalPassword)
                    }
                StalwartExclusiveLeaseAcquireResult.TimedOut ->
                    StalwartMailAccessResult.RetryableFailure(
                    projection(
                        account,
                        currentLocalStateOrRecovery(account),
                    ),
                    StalwartMailAccessReason.LeaseDrainTimedOut,
                )
            }
        } finally {
            normalPassword.close()
        }
    }

    suspend fun remove(
        account: StalwartMailAccount,
    ): StalwartMailAccessResult {
        if (account.accountId in protectedAccountIds) {
            return StalwartMailAccessResult.ReconciliationRequired(
                projection(
                    account,
                    StalwartMailAccessState.RecoveryRequired,
                ),
                StalwartMailAccessReason.ProtectedIdentity,
            )
        }
        return when (
            val exclusive = leases.acquireExclusive(account.accountId)
        ) {
            is StalwartExclusiveLeaseAcquireResult.Acquired ->
                exclusive.lease.use {
                    removeExclusive(account)
                }
            StalwartExclusiveLeaseAcquireResult.TimedOut ->
                StalwartMailAccessResult.RetryableFailure(
                projection(
                    account,
                    currentLocalStateOrRecovery(account),
                ),
                StalwartMailAccessReason.LeaseDrainTimedOut,
            )
        }
    }

    suspend fun rotate(
        account: StalwartMailAccount,
        normalPassword: StalwartNormalPassword,
    ): StalwartMailAccessResult {
        try {
            if (account.accountId in protectedAccountIds) {
                return StalwartMailAccessResult.ReconciliationRequired(
                    projection(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                    ),
                    StalwartMailAccessReason.ProtectedIdentity,
                )
            }
            return when (
                val exclusive = leases.acquireExclusive(account.accountId)
            ) {
                is StalwartExclusiveLeaseAcquireResult.Acquired ->
                    exclusive.lease.use {
                        rotateExclusive(account, normalPassword)
                    }
                StalwartExclusiveLeaseAcquireResult.TimedOut ->
                    StalwartMailAccessResult.RetryableFailure(
                    projection(
                        account,
                        currentLocalStateOrRecovery(account),
                    ),
                    StalwartMailAccessReason.LeaseDrainTimedOut,
                )
            }
        } finally {
            normalPassword.close()
        }
    }

    suspend fun reconcileAfterRestart(
        account: StalwartMailAccount,
    ): StalwartMailAccessResult {
        if (account.accountId in protectedAccountIds) {
            return reconciliation(
                account,
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessReason.ProtectedIdentity,
            )
        }
        return when (
            val exclusive = leases.acquireExclusive(account.accountId)
        ) {
            is StalwartExclusiveLeaseAcquireResult.Acquired ->
                exclusive.lease.use {
                    reconcileAfterRestartExclusive(account)
                }
            StalwartExclusiveLeaseAcquireResult.TimedOut ->
                StalwartMailAccessResult.RetryableFailure(
                projection(
                    account,
                    currentLocalStateOrRecovery(account),
                ),
                StalwartMailAccessReason.LeaseDrainTimedOut,
            )
        }
    }

    suspend fun resetUnavailableStore():
        StalwartCredentialStoreResetResult =
        when (val global = leases.acquireGlobalExclusive()) {
            is StalwartGlobalExclusiveLeaseAcquireResult.Acquired ->
                global.lease.use {
                    resetUnavailableStoreExclusive()
                }
            StalwartGlobalExclusiveLeaseAcquireResult.TimedOut ->
                StalwartCredentialStoreResetResult.RetryableFailure(
                StalwartMailAccessReason.LeaseDrainTimedOut,
            )
        }

    private suspend fun enrollExclusive(
        account: StalwartMailAccount,
        normalPassword: StalwartNormalPassword,
    ): StalwartMailAccessResult {
        val local = enrollmentLocalContext(account)
            ?: return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.StoreUnavailable),
                StalwartMailAccessReason.LocalStoreUnavailable,
            )
        return local.use { owned ->
            enrollExclusive(account, normalPassword, owned)
        }
    }

    private suspend fun enrollExclusive(
        account: StalwartMailAccount,
        normalPassword: StalwartNormalPassword,
        local: EnrollmentLocalContext,
    ): StalwartMailAccessResult {
        if (local.expected != null) {
            return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.RecoveryRequired),
                StalwartMailAccessReason.RemoteStateChanged,
            )
        }
        val inventory = when (
            val remote = management.inventory(account.accountId)
        ) {
            is StalwartRemoteRead.Available -> remote.value
            StalwartRemoteRead.Unavailable ->
                return StalwartMailAccessResult.RetryableFailure(
                    projection(
                        account,
                        StalwartMailAccessState.EnrollmentRequired,
                    ),
                    StalwartMailAccessReason.RemoteUnavailable,
                )
        }
        if (
            inventory.accountId != account.accountId ||
            inventory.reserved.isNotEmpty()
        ) {
            return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.RecoveryRequired),
                StalwartMailAccessReason.RemoteStateChanged,
            )
        }
        if (!inventory.quotaAvailable) {
            return StalwartMailAccessResult.RetryableFailure(
                projection(
                    account,
                    StalwartMailAccessState.EnrollmentRequired,
                ),
                StalwartMailAccessReason.CredentialQuotaFull,
            )
        }

        val generation = 1L
        val description =
            "$STALWART_RESERVED_DESCRIPTION_PREFIX${local.storeId}/$generation"
        return when (
            val create = owner.createOwned(
                account = account,
                description = description,
                normalPassword = normalPassword,
            )
        ) {
            is StalwartRemoteCreateResult.Created ->
                captureCreatedEnrollment(
                    account = account,
                    local = local,
                    generation = generation,
                    expectedDescription = description,
                    created = create.credential,
                )
            StalwartRemoteCreateResult.ResponseLost ->
                withContext(NonCancellable) {
                    cleanupUncaptured(
                        account = account,
                        cleanReason = StalwartMailAccessReason.CaptureFailed,
                        createdStamp = null,
                    )
                }
            StalwartRemoteCreateResult.Rejected ->
                StalwartMailAccessResult.RetryableFailure(
                    projection(
                        account,
                        StalwartMailAccessState.EnrollmentRequired,
                    ),
                    StalwartMailAccessReason.CredentialRejected,
                )
            StalwartRemoteCreateResult.Unavailable ->
                StalwartMailAccessResult.RetryableFailure(
                    projection(
                        account,
                        StalwartMailAccessState.EnrollmentRequired,
                    ),
                    StalwartMailAccessReason.RemoteUnavailable,
                )
        }
    }

    private suspend fun repairExclusive(
        account: StalwartMailAccount,
        normalPassword: StalwartNormalPassword,
    ): StalwartMailAccessResult {
        val local = enrollmentLocalContext(account)
            ?: return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.StoreUnavailable),
                StalwartMailAccessReason.LocalStoreUnavailable,
            )
        return local.use { owned ->
            repairExclusive(account, normalPassword, owned)
        }
    }

    private suspend fun repairExclusive(
        account: StalwartMailAccount,
        normalPassword: StalwartNormalPassword,
        local: EnrollmentLocalContext,
    ): StalwartMailAccessResult {
        val inventory = when (
            val remote = management.inventory(account.accountId)
        ) {
            is StalwartRemoteRead.Available -> remote.value
            StalwartRemoteRead.Unavailable ->
                return StalwartMailAccessResult.RetryableFailure(
                    projection(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                    ),
                    StalwartMailAccessReason.RemoteUnavailable,
                )
        }
        if (inventory.accountId != account.accountId) {
            return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.RecoveryRequired),
                StalwartMailAccessReason.RemoteStateChanged,
            )
        }
        if (
            inventory.reserved.isNotEmpty() &&
            management.revokeReserved(
                accountId = account.accountId,
                expected = inventory.reserved.toSet(),
            ) != StalwartRemoteMutationResult.Verified
        ) {
            return cleanupUnproven(account)
        }
        if (!inventory.quotaAvailableAfterReservedCleanup) {
            return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.RecoveryRequired),
                StalwartMailAccessReason.CredentialQuotaFull,
            )
        }

        val generation = nextGeneration(local, inventory)
            ?: return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.RecoveryRequired),
                StalwartMailAccessReason.RemoteStateChanged,
            )
        val description =
            "$STALWART_RESERVED_DESCRIPTION_PREFIX${local.storeId}/$generation"
        return when (
            val create = owner.createOwned(
                account = account,
                description = description,
                normalPassword = normalPassword,
            )
        ) {
            is StalwartRemoteCreateResult.Created ->
                captureCreatedEnrollment(
                    account = account,
                    local = local,
                    generation = generation,
                    expectedDescription = description,
                    created = create.credential,
                )
            StalwartRemoteCreateResult.ResponseLost ->
                withContext(NonCancellable) {
                    cleanupUncaptured(
                        account = account,
                        cleanReason = StalwartMailAccessReason.CaptureFailed,
                        createdStamp = null,
                    )
                }
            StalwartRemoteCreateResult.Rejected ->
                StalwartMailAccessResult.ReconciliationRequired(
                    projection(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                    ),
                    StalwartMailAccessReason.CredentialRejected,
                )
            StalwartRemoteCreateResult.Unavailable ->
                StalwartMailAccessResult.ReconciliationRequired(
                    projection(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                    ),
                    StalwartMailAccessReason.RemoteUnavailable,
                )
        }
    }

    private suspend fun removeExclusive(
        account: StalwartMailAccount,
    ): StalwartMailAccessResult {
        val local = localRecordStamp(account)
            ?: return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.StoreUnavailable),
                StalwartMailAccessReason.LocalStoreUnavailable,
            )
        try {
            val inventory = when (
                val remote = management.inventory(account.accountId)
            ) {
                is StalwartRemoteRead.Available -> remote.value
                StalwartRemoteRead.Unavailable ->
                    return StalwartMailAccessResult.RetryableFailure(
                        projection(
                            account,
                            StalwartMailAccessState.RecoveryRequired,
                        ),
                        StalwartMailAccessReason.RemoteUnavailable,
                    )
            }
            if (inventory.accountId != account.accountId) {
                return StalwartMailAccessResult.ReconciliationRequired(
                    projection(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                    ),
                    StalwartMailAccessReason.RemoteStateChanged,
                )
            }
            if (
                inventory.reserved.isNotEmpty() &&
                management.revokeReserved(
                    accountId = account.accountId,
                    expected = inventory.reserved.toSet(),
                ) != StalwartRemoteMutationResult.Verified
            ) {
                return cleanupUnproven(account)
            }
            val expected = local.stamp
                ?: return StalwartMailAccessResult.Completed(
                    projection(
                        account,
                        StalwartMailAccessState.EnrollmentRequired,
                    ),
                )

            val marker = removalPendingRecord(
                account = account,
                expected = expected,
            ) ?: return cleanupUnproven(account)
            marker.stamp().use { markerStamp ->
                val marked = commitAccount(
                    accountId = account.accountId,
                    expected = expected,
                    replacement = marker,
                )
                if (marked != LocalCommitResult.Committed) {
                    return removalFailureAfterWrite(
                        account = account,
                        markerStamp = markerStamp,
                    )
                }
                durablePhaseObserver.persisted(
                    account.accountId,
                    CredentialPhase.RemovalPending,
                )

                val erased = commitAccount(
                    accountId = account.accountId,
                    expected = markerStamp,
                    replacement = null,
                )
                if (erased == LocalCommitResult.Committed) {
                    return StalwartMailAccessResult.Completed(
                        projection(
                            account,
                            StalwartMailAccessState.EnrollmentRequired,
                        ),
                    )
                }
                return removalFailureAfterWrite(
                    account = account,
                    markerStamp = markerStamp,
                )
            }
        } finally {
            local.close()
        }
    }

    private suspend fun rotateExclusive(
        account: StalwartMailAccount,
        normalPassword: StalwartNormalPassword,
    ): StalwartMailAccessResult {
        val local = when (val read = loadRotationContext(account)) {
            is RotationLocalRead.Available -> read.context
            RotationLocalRead.Invalid ->
                return reconciliation(
                    account,
                    StalwartMailAccessState.RecoveryRequired,
                    StalwartMailAccessReason.RemoteStateChanged,
                )
            RotationLocalRead.StoreUnavailable ->
                return reconciliation(
                    account,
                    StalwartMailAccessState.StoreUnavailable,
                    StalwartMailAccessReason.LocalStoreUnavailable,
                )
        }
        local.use {
            val inventory = when (
                val remote = management.inventory(account.accountId)
            ) {
                is StalwartRemoteRead.Available -> remote.value
                StalwartRemoteRead.Unavailable ->
                    return StalwartMailAccessResult.RetryableFailure(
                        projection(
                            account,
                            StalwartMailAccessState.RecoveryRequired,
                        ),
                        StalwartMailAccessReason.RemoteUnavailable,
                    )
            }
            if (
                inventory.accountId != account.accountId ||
                inventory.reserved.size != 1 ||
                inventory.reserved.single() != local.old.reserved
            ) {
                return reconciliation(
                    account,
                    StalwartMailAccessState.RecoveryRequired,
                    StalwartMailAccessReason.RemoteStateChanged,
                )
            }
            if (!inventory.quotaAvailable) {
                return StalwartMailAccessResult.RetryableFailure(
                    projection(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                    ),
                    StalwartMailAccessReason.CredentialQuotaFull,
                )
            }
            if (local.old.generation == Long.MAX_VALUE) {
                return reconciliation(
                    account,
                    StalwartMailAccessState.RecoveryRequired,
                    StalwartMailAccessReason.RemoteStateChanged,
                )
            }

            val generation = local.old.generation + 1
            val description =
                "$STALWART_RESERVED_DESCRIPTION_PREFIX${local.storeId}/$generation"
            return when (
                val create = owner.createOwned(
                    account = account,
                    description = description,
                    normalPassword = normalPassword,
                )
            ) {
                is StalwartRemoteCreateResult.Created ->
                    rotateCreated(
                        account = account,
                        local = local,
                        generation = generation,
                        expectedDescription = description,
                        created = create.credential,
                    )
                StalwartRemoteCreateResult.ResponseLost ->
                    withContext(NonCancellable) {
                        cleanupLostRotationResponse(
                            account = account,
                            local = local,
                            expectedDescription = description,
                        )
                    }
                StalwartRemoteCreateResult.Rejected ->
                    StalwartMailAccessResult.RetryableFailure(
                        projection(
                            account,
                            StalwartMailAccessState.RecoveryRequired,
                        ),
                        StalwartMailAccessReason.CredentialRejected,
                    )
                StalwartRemoteCreateResult.Unavailable ->
                    StalwartMailAccessResult.RetryableFailure(
                        projection(
                            account,
                            StalwartMailAccessState.RecoveryRequired,
                        ),
                        StalwartMailAccessReason.RemoteUnavailable,
                    )
            }
        }
    }

    private suspend fun rotateCreated(
        account: StalwartMailAccount,
        local: RotationLocalContext,
        generation: Long,
        expectedDescription: String,
        created: StalwartCreatedCredential,
    ): StalwartMailAccessResult = created.use {
        val successorReserved = runCatching {
            StalwartReservedCredential(
                credentialId = created.credentialId,
                description = created.description,
            )
        }.getOrNull()
        if (
            created.description != expectedDescription ||
            successorReserved?.identity !=
            StalwartReservedCredentialIdentity.Exact(
                local.storeId,
                generation,
            ) ||
            successorReserved == local.old.reserved
        ) {
            return if (successorReserved == null) {
                cleanupUnproven(account)
            } else {
                cleanupDefinitiveCreated(account) {
                    cleanupRotationSuccessor(
                        account = account,
                        local = local,
                        successor = successorReserved,
                    )
                }
            }
        }

        created.takeSecret().use { successorSecret ->
            val successor = GenerationMaterial(
                credentialId = created.credentialId,
                description = created.description,
                generation = generation,
                secret = successorSecret,
            )
            val staged = rotationRecord(
                account = account,
                phase = CredentialPhase.Staged,
                active = local.old,
                other = successor,
            )
            staged.stamp().use { stagedStamp ->
                if (
                    commitAccount(
                        accountId = account.accountId,
                        expected = local.expected,
                        replacement = staged,
                    ) != LocalCommitResult.Committed
                ) {
                    return cleanupDefinitiveCreated(account) {
                        cleanupRotationSuccessor(
                            account = account,
                            local = local,
                            successor = successor.reserved,
                        )
                    }
                }
                durablePhaseObserver.persisted(
                    account.accountId,
                    CredentialPhase.Staged,
                )

                when (
                    val successorProbe = probeGeneration(account, successor)
                ) {
                    is StalwartCredentialProbeResult.Authenticated ->
                        if (
                            !successorProbe.capabilities.containsAll(
                                STALWART_REQUIRED_MAIL_CAPABILITIES,
                            )
                        ) {
                            return rotationPhaseFailure(
                                account,
                                StalwartMailAccessReason.CredentialRejected,
                            )
                        }
                    StalwartCredentialProbeResult.Rejected ->
                        return rotationPhaseFailure(
                            account,
                            StalwartMailAccessReason.CredentialRejected,
                        )
                    StalwartCredentialProbeResult.Unavailable ->
                        return rotationPhaseFailure(
                            account,
                            StalwartMailAccessReason.RemoteUnavailable,
                        )
                }

                val retiring = rotationRecord(
                    account = account,
                    phase = CredentialPhase.Retiring,
                    active = successor,
                    other = local.old,
                )
                retiring.stamp().use { retiringStamp ->
                    if (
                        commitAccount(
                            accountId = account.accountId,
                            expected = stagedStamp,
                            replacement = retiring,
                        ) != LocalCommitResult.Committed
                    ) {
                        return rotationPhaseFailure(
                            account,
                            StalwartMailAccessReason.LocalRevisionChanged,
                        )
                    }
                    durablePhaseObserver.persisted(
                        account.accountId,
                        CredentialPhase.Retiring,
                    )

                    val freshInventory = when (
                        val remote = management.inventory(account.accountId)
                    ) {
                        is StalwartRemoteRead.Available -> remote.value
                        StalwartRemoteRead.Unavailable ->
                            return rotationPhaseFailure(
                                account,
                                StalwartMailAccessReason.RemoteUnavailable,
                            )
                    }
                    if (
                        freshInventory.accountId != account.accountId ||
                        freshInventory.reserved.toSet() !=
                        setOf(local.old.reserved, successor.reserved) ||
                        freshInventory.reserved.size != 2
                    ) {
                        return rotationPhaseFailure(
                            account,
                            StalwartMailAccessReason.RemoteStateChanged,
                        )
                    }
                    if (
                        management.revokeReserved(
                            accountId = account.accountId,
                            expected =
                                setOf(local.old.reserved, successor.reserved),
                            targets = setOf(local.old.reserved),
                        ) != StalwartRemoteMutationResult.Verified
                    ) {
                        return rotationPhaseFailure(
                            account,
                            StalwartMailAccessReason.CleanupUnproven,
                        )
                    }

                    val oldProbe = probeGeneration(account, local.old)
                    val newProbe = probeGeneration(account, successor)
                    if (
                        oldProbe != StalwartCredentialProbeResult.Rejected ||
                        newProbe !is StalwartCredentialProbeResult.Authenticated ||
                        !newProbe.capabilities.containsAll(
                            STALWART_REQUIRED_MAIL_CAPABILITIES,
                        )
                    ) {
                        val reason = if (
                            oldProbe == StalwartCredentialProbeResult.Unavailable ||
                            newProbe == StalwartCredentialProbeResult.Unavailable
                        ) {
                            StalwartMailAccessReason.RemoteUnavailable
                        } else {
                            StalwartMailAccessReason.CredentialRejected
                        }
                        return rotationPhaseFailure(account, reason)
                    }

                    val active = rotationRecord(
                        account = account,
                        phase = CredentialPhase.Active,
                        active = successor,
                        other = null,
                    )
                    if (
                        commitAccount(
                            accountId = account.accountId,
                            expected = retiringStamp,
                            replacement = active,
                        ) != LocalCommitResult.Committed
                    ) {
                        return rotationPhaseFailure(
                            account,
                            StalwartMailAccessReason.LocalRevisionChanged,
                        )
                    }
                    return StalwartMailAccessResult.Completed(
                        projection(account, StalwartMailAccessState.Ready),
                    )
                }
            }
        }
    }

    private suspend fun reconcileAfterRestartExclusive(
        account: StalwartMailAccount,
    ): StalwartMailAccessResult {
        val local = when (val read = loadRestartContext(account)) {
            is RestartLocalRead.Available -> read.context
            RestartLocalRead.Invalid ->
                return reconciliation(
                    account,
                    StalwartMailAccessState.RecoveryRequired,
                    StalwartMailAccessReason.RemoteStateChanged,
                )
            RestartLocalRead.StoreUnavailable ->
                return reconciliation(
                    account,
                    StalwartMailAccessState.StoreUnavailable,
                    StalwartMailAccessReason.LocalStoreUnavailable,
                )
        }
        local.use {
            val inventory = when (
                val remote = management.inventory(account.accountId)
            ) {
                is StalwartRemoteRead.Available -> remote.value
                StalwartRemoteRead.Unavailable ->
                    return reconciliation(
                        account,
                        local.phase.projectedRestartState(),
                        StalwartMailAccessReason.RemoteUnavailable,
                    )
            }
            if (inventory.accountId != account.accountId) {
                return reconciliation(
                    account,
                    StalwartMailAccessState.RecoveryRequired,
                    StalwartMailAccessReason.RemoteStateChanged,
                )
            }
            return when (local.phase) {
                CredentialPhase.Staged ->
                    reconcileStaged(account, local, inventory)
                CredentialPhase.Retiring ->
                    reconcileRetiring(account, local, inventory)
                CredentialPhase.RemovalPending ->
                    reconcileRemovalPending(account, local, inventory)
                CredentialPhase.Active ->
                    reconciliation(
                        account,
                        StalwartMailAccessState.RecoveryRequired,
                        StalwartMailAccessReason.RemoteStateChanged,
                    )
            }
        }
    }

    private suspend fun reconcileStaged(
        account: StalwartMailAccount,
        local: RestartLocalContext,
        inventory: StalwartReservedInventory,
    ): StalwartMailAccessResult {
        val old = local.active
        val successor = local.other
            ?: return rotationPhaseFailure(
                account,
                StalwartMailAccessReason.RemoteStateChanged,
            )
        if (
            successor.generation <= old.generation ||
            inventory.reserved.size != 2 ||
            inventory.reserved.toSet() !=
            setOf(old.reserved, successor.reserved)
        ) {
            return reconciliation(
                account,
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessReason.RemoteStateChanged,
            )
        }

        val successorProbe = probeGeneration(account, successor)
        if (successorProbe.isMailAuthenticated()) {
            val retiring = rotationRecord(
                account = account,
                phase = CredentialPhase.Retiring,
                active = successor,
                other = old,
            )
            retiring.stamp().use { retiringStamp ->
                if (
                    commitAccount(
                        accountId = account.accountId,
                        expected = local.expected,
                        replacement = retiring,
                    ) != LocalCommitResult.Committed
                ) {
                    return rotationPhaseFailure(
                        account,
                        StalwartMailAccessReason.LocalRevisionChanged,
                    )
                }
                durablePhaseObserver.persisted(
                    account.accountId,
                    CredentialPhase.Retiring,
                )
                return finishRetiring(
                    account = account,
                    expected = retiringStamp,
                    successor = successor,
                    old = old,
                    inventory = null,
                )
            }
        }
        if (successorProbe == StalwartCredentialProbeResult.Unavailable) {
            return rotationPhaseFailure(
                account,
                StalwartMailAccessReason.RemoteUnavailable,
            )
        }

        val oldProbe = probeGeneration(account, old)
        if (!oldProbe.isMailAuthenticated()) {
            val reason =
                if (oldProbe == StalwartCredentialProbeResult.Unavailable) {
                    StalwartMailAccessReason.RemoteUnavailable
                } else {
                    StalwartMailAccessReason.CredentialRejected
                }
            return rotationPhaseFailure(account, reason)
        }
        if (
            management.revokeReserved(
                accountId = account.accountId,
                expected = setOf(old.reserved, successor.reserved),
                targets = setOf(successor.reserved),
            ) != StalwartRemoteMutationResult.Verified
        ) {
            return rotationPhaseFailure(
                account,
                StalwartMailAccessReason.CleanupUnproven,
            )
        }
        val restored = rotationRecord(
            account = account,
            phase = CredentialPhase.Active,
            active = old,
            other = null,
        )
        if (
            commitAccount(
                accountId = account.accountId,
                expected = local.expected,
                replacement = restored,
            ) != LocalCommitResult.Committed
        ) {
            return rotationPhaseFailure(
                account,
                StalwartMailAccessReason.LocalRevisionChanged,
            )
        }
        return StalwartMailAccessResult.Completed(
            projection(account, StalwartMailAccessState.Ready),
        )
    }

    private suspend fun reconcileRetiring(
        account: StalwartMailAccount,
        local: RestartLocalContext,
        inventory: StalwartReservedInventory,
    ): StalwartMailAccessResult {
        val successor = local.active
        val old = local.other
            ?: return rotationPhaseFailure(
                account,
                StalwartMailAccessReason.RemoteStateChanged,
            )
        if (successor.generation <= old.generation) {
            return reconciliation(
                account,
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessReason.RemoteStateChanged,
            )
        }
        return finishRetiring(
            account = account,
            expected = local.expected,
            successor = successor,
            old = old,
            inventory = inventory,
        )
    }

    private suspend fun finishRetiring(
        account: StalwartMailAccount,
        expected: RecordStamp,
        successor: GenerationMaterial,
        old: GenerationMaterial,
        inventory: StalwartReservedInventory?,
    ): StalwartMailAccessResult {
        val fresh = inventory ?: when (
            val remote = management.inventory(account.accountId)
        ) {
            is StalwartRemoteRead.Available -> remote.value
            StalwartRemoteRead.Unavailable ->
                return rotationPhaseFailure(
                    account,
                    StalwartMailAccessReason.RemoteUnavailable,
                )
        }
        if (fresh.accountId != account.accountId) {
            return reconciliation(
                account,
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessReason.RemoteStateChanged,
            )
        }
        val both = setOf(successor.reserved, old.reserved)
        val successorOnly = setOf(successor.reserved)
        val actual = fresh.reserved.toSet()
        if (
            fresh.reserved.size != actual.size ||
            actual != both && actual != successorOnly
        ) {
            return reconciliation(
                account,
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessReason.RemoteStateChanged,
            )
        }
        if (
            actual == both &&
            management.revokeReserved(
                accountId = account.accountId,
                expected = both,
                targets = setOf(old.reserved),
            ) != StalwartRemoteMutationResult.Verified
        ) {
            return rotationPhaseFailure(
                account,
                StalwartMailAccessReason.CleanupUnproven,
            )
        }

        val oldProbe = probeGeneration(account, old)
        val successorProbe = probeGeneration(account, successor)
        if (
            oldProbe != StalwartCredentialProbeResult.Rejected ||
            !successorProbe.isMailAuthenticated()
        ) {
            val reason = if (
                oldProbe == StalwartCredentialProbeResult.Unavailable ||
                successorProbe == StalwartCredentialProbeResult.Unavailable
            ) {
                StalwartMailAccessReason.RemoteUnavailable
            } else {
                StalwartMailAccessReason.CredentialRejected
            }
            return rotationPhaseFailure(account, reason)
        }

        val active = rotationRecord(
            account = account,
            phase = CredentialPhase.Active,
            active = successor,
            other = null,
        )
        if (
            commitAccount(
                accountId = account.accountId,
                expected = expected,
                replacement = active,
            ) != LocalCommitResult.Committed
        ) {
            return rotationPhaseFailure(
                account,
                StalwartMailAccessReason.LocalRevisionChanged,
            )
        }
        return StalwartMailAccessResult.Completed(
            projection(account, StalwartMailAccessState.Ready),
        )
    }

    private fun reconcileRemovalPending(
        account: StalwartMailAccount,
        local: RestartLocalContext,
        inventory: StalwartReservedInventory,
    ): StalwartMailAccessResult {
        if (inventory.reserved.isNotEmpty()) {
            return reconciliation(
                account,
                StalwartMailAccessState.RecoveryRequired,
                StalwartMailAccessReason.RemoteStateChanged,
            )
        }
        if (
            commitAccount(
                accountId = account.accountId,
                expected = local.expected,
                replacement = null,
            ) == LocalCommitResult.Committed
        ) {
            return StalwartMailAccessResult.Completed(
                projection(
                    account,
                    StalwartMailAccessState.EnrollmentRequired,
                ),
            )
        }
        return removalFailureAfterWrite(
            account = account,
            markerStamp = local.expected,
        )
    }

    private suspend fun resetUnavailableStoreExclusive():
        StalwartCredentialStoreResetResult {
        when (val preflight = store.load()) {
            is CredentialStoreLoadResult.Available -> {
                preflight.snapshot.close()
                return resetNeedsManualRemediation()
            }
            CredentialStoreLoadResult.StoreUnavailable -> Unit
        }

        val initial = when (val remote = management.globalInventory()) {
            is StalwartRemoteRead.Available -> remote.value
            StalwartRemoteRead.Unavailable ->
                return StalwartCredentialStoreResetResult.RetryableFailure(
                    StalwartMailAccessReason.RemoteUnavailable,
                )
        }
        val retiredStoreIds = initial.reserved.mapNotNull { (_, credential) ->
            when (val identity = credential.identity) {
                is StalwartReservedCredentialIdentity.Exact ->
                    identity.storeId
                StalwartReservedCredentialIdentity.Malformed -> null
            }
        }.toSet()

        initial.accounts.forEach { account ->
            if (
                account.reserved.isNotEmpty() &&
                management.revokeReserved(
                    accountId = account.accountId,
                    expected = account.reserved.toSet(),
                ) != StalwartRemoteMutationResult.Verified
            ) {
                return StalwartCredentialStoreResetResult.ReconciliationRequired(
                    StalwartMailAccessReason.CleanupUnproven,
                )
            }
        }

        val verified = when (val remote = management.globalInventory()) {
            is StalwartRemoteRead.Available -> remote.value
            StalwartRemoteRead.Unavailable ->
                return StalwartCredentialStoreResetResult.ReconciliationRequired(
                    StalwartMailAccessReason.CleanupUnproven,
                )
        }
        val initialAccounts = initial.accounts.associate {
            it.accountId to it.protectedIdentity
        }
        val verifiedAccounts = verified.accounts.associate {
            it.accountId to it.protectedIdentity
        }
        if (
            verifiedAccounts != initialAccounts ||
            verified.reserved.isNotEmpty()
        ) {
            return StalwartCredentialStoreResetResult.ReconciliationRequired(
                StalwartMailAccessReason.CleanupUnproven,
            )
        }

        return when (store.quarantineUnavailable()) {
            is CredentialStoreQuarantineResult.Quarantined ->
                validateFreshStore(retiredStoreIds)
            is CredentialStoreQuarantineResult.PartiallyQuarantined,
            CredentialStoreQuarantineResult.StoreAvailable,
            CredentialStoreQuarantineResult.StoreUnavailable,
            -> resetNeedsManualRemediation()
        }
    }

    private fun validateFreshStore(
        retiredStoreIds: Set<java.util.UUID>,
    ): StalwartCredentialStoreResetResult {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return resetNeedsManualRemediation()
        loaded.snapshot.use { snapshot ->
            if (
                snapshot.revision != 0L ||
                snapshot.records.isNotEmpty() ||
                snapshot.storeId in retiredStoreIds
            ) {
                return resetNeedsManualRemediation()
            }
            return StalwartCredentialStoreResetResult.Completed(
                snapshot.storeId,
            )
        }
    }

    private fun resetNeedsManualRemediation():
        StalwartCredentialStoreResetResult =
        StalwartCredentialStoreResetResult.ReconciliationRequired(
            StalwartMailAccessReason.ResetNeedsManualRemediation,
        )

    private suspend fun captureCreatedEnrollment(
        account: StalwartMailAccount,
        local: EnrollmentLocalContext,
        generation: Long,
        expectedDescription: String,
        created: StalwartCreatedCredential,
    ): StalwartMailAccessResult = created.use {
        if (
            created.description != expectedDescription ||
            runCatching {
                StalwartReservedCredential(
                    created.credentialId,
                    created.description,
                )
            }.getOrNull()?.identity !=
            StalwartReservedCredentialIdentity.Exact(
                local.storeId,
                generation,
            )
        ) {
            return cleanupDefinitiveCreated(account) {
                cleanupUncaptured(
                    account = account,
                    cleanReason = StalwartMailAccessReason.CaptureFailed,
                    createdStamp = null,
                )
            }
        }

        created.takeSecret().use { captured ->
            val persistentBytes = captured.withBytes(ByteArray::copyOf)
            val replacement = try {
                activeRecord(
                    account = account,
                    credentialId = created.credentialId,
                    description = created.description,
                    generation = generation,
                    secret = persistentBytes,
                )
            } catch (failure: Throwable) {
                persistentBytes.fill(0)
                throw failure
            }
            replacement.stamp().use { createdStamp ->
                val commit = commitAccount(
                    accountId = account.accountId,
                    expected = local.expected,
                    replacement = replacement,
                )
                if (commit != LocalCommitResult.Committed) {
                    return cleanupDefinitiveCreated(account) {
                        cleanupUncaptured(
                            account = account,
                            cleanReason = StalwartMailAccessReason.CaptureFailed,
                            createdStamp = createdStamp,
                        )
                    }
                }

                return when (
                    val result = probe.probe(
                        accountId = account.accountId,
                        address = account.address,
                        secret = captured,
                    )
                ) {
                    is StalwartCredentialProbeResult.Authenticated ->
                        if (
                            result.capabilities.containsAll(
                                STALWART_REQUIRED_MAIL_CAPABILITIES,
                            )
                        ) {
                            StalwartMailAccessResult.Completed(
                                projection(
                                    account,
                                    StalwartMailAccessState.Ready,
                                ),
                            )
                        } else {
                            StalwartMailAccessResult.ReconciliationRequired(
                                projection(
                                    account,
                                    StalwartMailAccessState.RecoveryRequired,
                                ),
                                StalwartMailAccessReason.CredentialRejected,
                            )
                        }
                    StalwartCredentialProbeResult.Rejected ->
                        StalwartMailAccessResult.ReconciliationRequired(
                            projection(
                                account,
                                StalwartMailAccessState.RecoveryRequired,
                            ),
                            StalwartMailAccessReason.CredentialRejected,
                        )
                    StalwartCredentialProbeResult.Unavailable ->
                        StalwartMailAccessResult.ReconciliationRequired(
                            projection(
                                account,
                                StalwartMailAccessState.RecoveryRequired,
                            ),
                            StalwartMailAccessReason.RemoteUnavailable,
                        )
                }
            }
        }
    }

    private suspend fun cleanupDefinitiveCreated(
        account: StalwartMailAccount,
        cleanup: suspend () -> StalwartMailAccessResult,
    ): StalwartMailAccessResult = withContext(NonCancellable) {
        withTimeoutOrNull(definitiveCreatedCleanupTimeout) {
            cleanup()
        } ?: cleanupUnproven(account)
    }

    private suspend fun cleanupUncaptured(
        account: StalwartMailAccount,
        cleanReason: StalwartMailAccessReason,
        createdStamp: RecordStamp?,
    ): StalwartMailAccessResult {
        val inventory = when (
            val remote = management.inventory(account.accountId)
        ) {
            is StalwartRemoteRead.Available -> remote.value
            StalwartRemoteRead.Unavailable ->
                return cleanupUnproven(account)
        }
        if (inventory.accountId != account.accountId) {
            return cleanupUnproven(account)
        }
        val cleanup = if (inventory.reserved.isEmpty()) {
            StalwartRemoteMutationResult.Verified
        } else {
            management.revokeReserved(
                accountId = account.accountId,
                expected = inventory.reserved.toSet(),
            )
        }
        if (cleanup != StalwartRemoteMutationResult.Verified) {
            return cleanupUnproven(account)
        }
        return reconcileLocalAfterUncapturedCleanup(
            account = account,
            cleanReason = cleanReason,
            createdStamp = createdStamp,
        )
    }

    /**
     * A lost create response has no trustworthy local stamp, so it may only
     * prove that the target is absent. A captured create may erase the exact
     * record it attempted to persist, but never an unknown concurrent record.
     */
    private fun reconcileLocalAfterUncapturedCleanup(
        account: StalwartMailAccount,
        cleanReason: StalwartMailAccessReason,
        createdStamp: RecordStamp?,
    ): StalwartMailAccessResult {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return cleanupUnproven(account)
        val currentMatchesCreated = loaded.snapshot.use { snapshot ->
            val current = snapshot.records[account.accountId]
                ?: return@use null
            createdStamp != null && current.matchesStamp(createdStamp)
        }
        if (currentMatchesCreated == null) {
            return enrollmentRequiredAfterCleanup(account, cleanReason)
        }
        if (!currentMatchesCreated) {
            return cleanupUnproven(account)
        }

        val erase = commitAccount(
            accountId = account.accountId,
            expected = createdStamp,
            replacement = null,
        )
        if (erase == LocalCommitResult.Committed) {
            return enrollmentRequiredAfterCleanup(account, cleanReason)
        }

        val verified = store.load() as? CredentialStoreLoadResult.Available
            ?: return cleanupUnproven(account)
        val isAbsent = verified.snapshot.use { snapshot ->
            snapshot.records[account.accountId] == null
        }
        return if (isAbsent) {
            enrollmentRequiredAfterCleanup(account, cleanReason)
        } else {
            cleanupUnproven(account)
        }
    }

    private fun enrollmentRequiredAfterCleanup(
        account: StalwartMailAccount,
        cleanReason: StalwartMailAccessReason,
    ): StalwartMailAccessResult =
        StalwartMailAccessResult.ReconciliationRequired(
            projection(
                account,
                StalwartMailAccessState.EnrollmentRequired,
            ),
            cleanReason,
        )

    private fun cleanupUnproven(
        account: StalwartMailAccount,
    ): StalwartMailAccessResult =
        StalwartMailAccessResult.ReconciliationRequired(
            projection(account, StalwartMailAccessState.RecoveryRequired),
            StalwartMailAccessReason.CleanupUnproven,
        )

    private fun enrollmentLocalContext(
        account: StalwartMailAccount,
    ): EnrollmentLocalContext? {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return null
        loaded.snapshot.use { snapshot ->
            val record = snapshot.records[account.accountId]
            val expected = record?.stamp()
            return try {
                EnrollmentLocalContext(
                    storeId = snapshot.storeId,
                    expected = expected,
                    maxLocalGeneration = record?.let(::maxGeneration) ?: 0,
                )
            } catch (failure: Throwable) {
                expected?.close()
                throw failure
            }
        }
    }

    private fun localRecordStamp(
        account: StalwartMailAccount,
    ): LocalRecordContext? {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return null
        loaded.snapshot.use { snapshot ->
            val stamp = snapshot.records[account.accountId]?.stamp()
            return try {
                LocalRecordContext(stamp)
            } catch (failure: Throwable) {
                stamp?.close()
                throw failure
            }
        }
    }

    private fun nextGeneration(
        local: EnrollmentLocalContext,
        inventory: StalwartReservedInventory,
    ): Long? {
        val maxRemote = inventory.reserved.maxOfOrNull { credential ->
            when (val identity = credential.identity) {
                is StalwartReservedCredentialIdentity.Exact ->
                    identity.generation.takeIf {
                        identity.storeId == local.storeId
                    } ?: 0
                StalwartReservedCredentialIdentity.Malformed -> 0
            }
        } ?: 0
        val maximum = maxOf(local.maxLocalGeneration, maxRemote)
        return if (maximum == Long.MAX_VALUE) null else maximum + 1
    }

    private val StalwartReservedInventory.quotaAvailableAfterReservedCleanup:
        Boolean
        get() {
            val remainingCount = appPasswordCount - reserved.size
            return appPasswordLimit == null || remainingCount < appPasswordLimit
        }

    private fun maxGeneration(
        record: StalwartCredentialRecord,
    ): Long = maxOf(
        record.active?.generation ?: 0,
        record.other?.generation ?: 0,
    )

    private fun removalPendingRecord(
        account: StalwartMailAccount,
        expected: RecordStamp,
    ): StalwartCredentialRecord? {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return null
        loaded.snapshot.use { snapshot ->
            val current = snapshot.records[account.accountId]
                ?.takeIf { it.matchesStamp(expected) }
                ?: return null
            val active = current.active ?: return null
            val copied = active.copyGeneration()
            return StalwartCredentialRecord.takeOwnership(
                accountId = current.accountId,
                addressAtCapture = current.addressAtCapture,
                phase = CredentialPhase.RemovalPending,
                active = copied,
                other = null,
            )
        }
    }

    private fun CredentialGeneration.copyGeneration(): CredentialGeneration {
        val bytes = secret.copyForUse()
        val owned = SecretBytes.takeOwnership(bytes)
        return try {
            CredentialGeneration(
                credentialId = credentialId,
                description = description,
                generation = generation,
                secret = owned,
            )
        } catch (failure: Throwable) {
            owned.close()
            throw failure
        }
    }

    private fun removalFailureAfterWrite(
        account: StalwartMailAccount,
        markerStamp: RecordStamp,
    ): StalwartMailAccessResult {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return StalwartMailAccessResult.ReconciliationRequired(
                projection(account, StalwartMailAccessState.StoreUnavailable),
                StalwartMailAccessReason.LocalStoreUnavailable,
            )
        return loaded.snapshot.use { snapshot ->
            val current = snapshot.records[account.accountId]
            when {
                current == null -> StalwartMailAccessResult.Completed(
                    projection(
                        account,
                        StalwartMailAccessState.EnrollmentRequired,
                    ),
                )
                current.matchesStamp(markerStamp) ->
                    StalwartMailAccessResult.ReconciliationRequired(
                        projection(
                            account,
                            StalwartMailAccessState.RemovalPending,
                        ),
                        StalwartMailAccessReason.LocalStoreUnavailable,
                    )
                else -> cleanupUnproven(account)
            }
        }
    }

    private fun loadRotationContext(
        account: StalwartMailAccount,
    ): RotationLocalRead {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return RotationLocalRead.StoreUnavailable
        return loaded.snapshot.use { snapshot ->
            val record = snapshot.records[account.accountId]
                ?.takeIf {
                    it.phase == CredentialPhase.Active &&
                        it.addressAtCapture == account.address
                }
                ?: return@use RotationLocalRead.Invalid
            val active = record.active
                ?: return@use RotationLocalRead.Invalid
            val reserved = runCatching {
                StalwartReservedCredential(
                    credentialId = active.credentialId,
                    description = active.description,
                )
            }.getOrNull() ?: return@use RotationLocalRead.Invalid
            if (
                reserved.identity != StalwartReservedCredentialIdentity.Exact(
                    storeId = snapshot.storeId,
                    generation = active.generation,
                )
            ) {
                return@use RotationLocalRead.Invalid
            }
            val copied = active.secret.copyForUse()
            val borrowed = try {
                StalwartBorrowedSecret.takeOwnership(copied)
            } catch (failure: Throwable) {
                copied.fill(0)
                throw failure
            }
            val old = GenerationMaterial(
                credentialId = active.credentialId,
                description = active.description,
                generation = active.generation,
                secret = borrowed,
            )
            val expected = try {
                record.stamp()
            } catch (failure: Throwable) {
                old.secret.close()
                throw failure
            }
            try {
                RotationLocalRead.Available(
                    RotationLocalContext(
                        storeId = snapshot.storeId,
                        expected = expected,
                        old = old,
                    ),
                )
            } catch (failure: Throwable) {
                expected.close()
                old.secret.close()
                throw failure
            }
        }
    }

    private fun loadRestartContext(
        account: StalwartMailAccount,
    ): RestartLocalRead {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return RestartLocalRead.StoreUnavailable
        return loaded.snapshot.use { snapshot ->
            val record = snapshot.records[account.accountId]
                ?.takeIf {
                    it.phase != CredentialPhase.Active &&
                        it.addressAtCapture == account.address
                }
                ?: return@use RestartLocalRead.Invalid
            val active = record.active
                ?.let { generationMaterial(snapshot.storeId, it) }
                ?: return@use RestartLocalRead.Invalid
            val other = if (record.other == null) {
                null
            } else {
                generationMaterial(snapshot.storeId, record.other)
                    ?: run {
                        active.secret.close()
                        return@use RestartLocalRead.Invalid
                    }
            }
            val expected = try {
                record.stamp()
            } catch (failure: Throwable) {
                active.secret.close()
                other?.secret?.close()
                throw failure
            }
            try {
                RestartLocalRead.Available(
                    RestartLocalContext(
                        expected = expected,
                        phase = record.phase,
                        active = active,
                        other = other,
                    ),
                )
            } catch (failure: Throwable) {
                expected.close()
                active.secret.close()
                other?.secret?.close()
                throw failure
            }
        }
    }

    private fun generationMaterial(
        storeId: java.util.UUID,
        generation: CredentialGeneration,
    ): GenerationMaterial? {
        val reserved = runCatching {
            StalwartReservedCredential(
                credentialId = generation.credentialId,
                description = generation.description,
            )
        }.getOrNull() ?: return null
        if (
            reserved.identity != StalwartReservedCredentialIdentity.Exact(
                storeId = storeId,
                generation = generation.generation,
            )
        ) {
            return null
        }
        val copied = generation.secret.copyForUse()
        val borrowed = try {
            StalwartBorrowedSecret.takeOwnership(copied)
        } catch (failure: Throwable) {
            copied.fill(0)
            throw failure
        }
        return try {
            GenerationMaterial(
                credentialId = generation.credentialId,
                description = generation.description,
                generation = generation.generation,
                secret = borrowed,
            )
        } catch (failure: Throwable) {
            borrowed.close()
            throw failure
        }
    }

    private suspend fun cleanupRotationSuccessor(
        account: StalwartMailAccount,
        local: RotationLocalContext,
        successor: StalwartReservedCredential,
    ): StalwartMailAccessResult {
        if (successor == local.old.reserved) {
            return cleanupUnproven(account)
        }
        if (
            management.revokeReserved(
                accountId = account.accountId,
                expected = setOf(local.old.reserved, successor),
                targets = setOf(successor),
            ) != StalwartRemoteMutationResult.Verified
        ) {
            return cleanupUnproven(account)
        }
        return rotationPhaseFailure(
            account,
            StalwartMailAccessReason.CaptureFailed,
        )
    }

    private suspend fun cleanupLostRotationResponse(
        account: StalwartMailAccount,
        local: RotationLocalContext,
        expectedDescription: String,
    ): StalwartMailAccessResult {
        val inventory = when (
            val remote = management.inventory(account.accountId)
        ) {
            is StalwartRemoteRead.Available -> remote.value
            StalwartRemoteRead.Unavailable ->
                return cleanupUnproven(account)
        }
        if (
            inventory.accountId != account.accountId ||
            local.old.reserved !in inventory.reserved
        ) {
            return cleanupUnproven(account)
        }
        val additions = inventory.reserved.filterNot {
            it == local.old.reserved
        }
        if (additions.isEmpty()) {
            return rotationPhaseFailure(
                account,
                StalwartMailAccessReason.CaptureFailed,
            )
        }
        val successor = additions.singleOrNull()
            ?.takeIf { it.description == expectedDescription }
            ?: return cleanupUnproven(account)
        return cleanupRotationSuccessor(
            account = account,
            local = local,
            successor = successor,
        )
    }

    private fun rotationRecord(
        account: StalwartMailAccount,
        phase: CredentialPhase,
        active: GenerationMaterial,
        other: GenerationMaterial?,
    ): StalwartCredentialRecord {
        val activeGeneration = active.toGeneration()
        var otherGeneration: CredentialGeneration? = null
        return try {
            otherGeneration = other?.toGeneration()
            StalwartCredentialRecord.takeOwnership(
                accountId = account.accountId,
                addressAtCapture = account.address,
                phase = phase,
                active = activeGeneration,
                other = otherGeneration,
            )
        } catch (failure: Throwable) {
            activeGeneration.close()
            otherGeneration?.close()
            throw failure
        }
    }

    private fun GenerationMaterial.toGeneration(): CredentialGeneration =
        secret.withBytes { borrowed ->
            val persistent = borrowed.copyOf()
            val owned = try {
                SecretBytes.takeOwnership(persistent)
            } catch (failure: Throwable) {
                persistent.fill(0)
                throw failure
            }
            try {
                CredentialGeneration(
                    credentialId = credentialId,
                    description = description,
                    generation = generation,
                    secret = owned,
                )
            } catch (failure: Throwable) {
                owned.close()
                throw failure
            }
        }

    private suspend fun probeGeneration(
        account: StalwartMailAccount,
        material: GenerationMaterial,
    ): StalwartCredentialProbeResult =
        probe.probe(
            accountId = account.accountId,
            address = account.address,
            secret = material.secret,
        )

    private fun StalwartCredentialProbeResult.isMailAuthenticated(): Boolean =
        this is StalwartCredentialProbeResult.Authenticated &&
            capabilities.containsAll(STALWART_REQUIRED_MAIL_CAPABILITIES)

    private fun CredentialPhase.projectedRestartState():
        StalwartMailAccessState = when (this) {
        CredentialPhase.Staged,
        CredentialPhase.Retiring,
        -> StalwartMailAccessState.Rotating
        CredentialPhase.RemovalPending ->
            StalwartMailAccessState.RemovalPending
        CredentialPhase.Active ->
            StalwartMailAccessState.RecoveryRequired
    }

    private fun rotationPhaseFailure(
        account: StalwartMailAccount,
        reason: StalwartMailAccessReason,
    ): StalwartMailAccessResult {
        val local = currentLocalStateOrRecovery(account)
        val state = if (local == StalwartMailAccessState.EnrollmentRequired) {
            StalwartMailAccessState.RecoveryRequired
        } else {
            local
        }
        return reconciliation(account, state, reason)
    }

    private fun reconciliation(
        account: StalwartMailAccount,
        state: StalwartMailAccessState,
        reason: StalwartMailAccessReason,
    ): StalwartMailAccessResult =
        StalwartMailAccessResult.ReconciliationRequired(
            projection(account, state),
            reason,
        )

    private fun activeRecord(
        account: StalwartMailAccount,
        credentialId: String,
        description: String,
        generation: Long,
        secret: ByteArray,
    ): StalwartCredentialRecord {
        val ownedSecret = SecretBytes.takeOwnership(secret)
        val ownedGeneration = try {
            CredentialGeneration(
                credentialId = credentialId,
                description = description,
                generation = generation,
                secret = ownedSecret,
            )
        } catch (failure: Throwable) {
            ownedSecret.close()
            throw failure
        }
        return StalwartCredentialRecord.takeOwnership(
            accountId = account.accountId,
            addressAtCapture = account.address,
            phase = CredentialPhase.Active,
            active = ownedGeneration,
            other = null,
        )
    }

    private fun commitAccount(
        accountId: String,
        expected: RecordStamp?,
        replacement: StalwartCredentialRecord?,
    ): LocalCommitResult = try {
        storeWriteLock.withLock {
            repeat(MAX_LOCAL_COMMIT_ATTEMPTS) {
                val loaded = store.load() as? CredentialStoreLoadResult.Available
                    ?: return@withLock LocalCommitResult.StoreUnavailable
                loaded.snapshot.use { snapshot ->
                    if (!snapshot.records[accountId].matchesStamp(expected)) {
                        return@withLock LocalCommitResult.TargetChanged
                    }
                    val merged = LinkedHashMap(snapshot.records)
                    if (replacement == null) {
                        merged.remove(accountId)
                    } else {
                        merged[accountId] = replacement
                    }
                    when (
                        store.replace(
                            expectedRevision = snapshot.revision,
                            records = merged,
                        )
                    ) {
                        is CredentialStoreWriteResult.Written ->
                            return@withLock LocalCommitResult.Committed
                        is CredentialStoreWriteResult.RevisionMismatch -> Unit
                        CredentialStoreWriteResult.StoreUnavailable ->
                            return@withLock LocalCommitResult.StoreUnavailable
                    }
                }
            }
            LocalCommitResult.RevisionChanged
        }
    } finally {
        replacement?.close()
    }

    private fun StalwartCredentialRecord.stamp(): RecordStamp {
        val activeStamp = active?.stamp()
        val otherStamp = try {
            other?.stamp()
        } catch (failure: Throwable) {
            activeStamp?.close()
            throw failure
        }
        return try {
            RecordStamp(
                accountId = accountId,
                addressAtCapture = addressAtCapture,
                phase = phase,
                active = activeStamp,
                other = otherStamp,
            )
        } catch (failure: Throwable) {
            activeStamp?.close()
            otherStamp?.close()
            throw failure
        }
    }

    private fun StalwartCredentialRecord?.matchesStamp(
        expected: RecordStamp?,
    ): Boolean {
        if (this == null || expected == null) {
            return this == null && expected == null
        }
        return stamp().use { current ->
            current == expected
        }
    }

    private fun CredentialGeneration.stamp(): GenerationStamp {
        val fingerprintBytes = secret.read { secretBytes ->
            MessageDigest.getInstance("SHA-256").digest(secretBytes)
        }
        val fingerprint = SecretFingerprint.takeOwnership(fingerprintBytes)
        return try {
            GenerationStamp(
                credentialId = credentialId,
                description = description,
                generation = generation,
                secretFingerprint = fingerprint,
            )
        } catch (failure: Throwable) {
            fingerprint.close()
            throw failure
        }
    }

    private fun currentLocalStateOrRecovery(
        account: StalwartMailAccount,
    ): StalwartMailAccessState {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return StalwartMailAccessState.StoreUnavailable
        loaded.snapshot.use { snapshot ->
            val record = snapshot.records[account.accountId]
                ?: return StalwartMailAccessState.EnrollmentRequired
            return when (record.phase) {
                CredentialPhase.Active ->
                    StalwartMailAccessState.RecoveryRequired
                CredentialPhase.Staged,
                CredentialPhase.Retiring,
                -> StalwartMailAccessState.Rotating
                CredentialPhase.RemovalPending ->
                    StalwartMailAccessState.RemovalPending
            }
        }
    }

    private suspend fun loadReadyMaterial(
        account: StalwartMailAccount,
    ): StalwartMailLeaseMaterial? {
        val loaded = store.load() as? CredentialStoreLoadResult.Available
            ?: return null
        loaded.snapshot.use { snapshot ->
            val record = snapshot.records[account.accountId]
                ?.takeIf {
                    it.phase == CredentialPhase.Active &&
                        it.addressAtCapture == account.address
                }
                ?: return null
            val active = record.active ?: return null
            val inventory = when (
                val remote = management.inventory(account.accountId)
            ) {
                is StalwartRemoteRead.Available -> remote.value
                StalwartRemoteRead.Unavailable -> return null
            }
            if (
                inventory.accountId != account.accountId ||
                !matchesExactly(snapshot, record, inventory)
            ) {
                return null
            }
            if (!probeAuthenticated(account, active)) return null
            val leaseCopy = active.secret.copyForUse()
            return try {
                StalwartMailLeaseMaterial.takeOwnership(
                    accountId = account.accountId,
                    generation = active.generation,
                    secret = leaseCopy,
                )
            } catch (failure: Throwable) {
                leaseCopy.fill(0)
                throw failure
            }
        }
    }

    private suspend fun projectAvailable(
        account: StalwartMailAccount,
        snapshot: StalwartCredentialSnapshot,
        record: StalwartCredentialRecord?,
        inventory: StalwartReservedInventory,
    ): StalwartMailAccessProjection {
        if (record == null) {
            return projection(
                account,
                if (inventory.reserved.isEmpty()) {
                    StalwartMailAccessState.EnrollmentRequired
                } else {
                    StalwartMailAccessState.RecoveryRequired
                },
            )
        }

        return when (record.phase) {
            CredentialPhase.Staged -> projection(
                account,
                if (matchesExactly(snapshot, record, inventory)) {
                    StalwartMailAccessState.Rotating
                } else {
                    StalwartMailAccessState.RecoveryRequired
                },
            )

            CredentialPhase.Retiring -> projection(
                account,
                if (matchesRetiring(snapshot, record, inventory)) {
                    StalwartMailAccessState.Rotating
                } else {
                    StalwartMailAccessState.RecoveryRequired
                },
            )

            CredentialPhase.RemovalPending -> projection(
                account,
                if (inventory.reserved.isEmpty()) {
                    StalwartMailAccessState.RemovalPending
                } else {
                    StalwartMailAccessState.RecoveryRequired
                },
            )

            CredentialPhase.Active -> {
                val active = record.active
                if (
                    active != null &&
                    matchesExactly(snapshot, record, inventory) &&
                    probeAuthenticated(account, active)
                ) {
                    projection(account, StalwartMailAccessState.Ready)
                } else {
                    projection(account, StalwartMailAccessState.RecoveryRequired)
                }
            }
        }
    }

    private fun matchesExactly(
        snapshot: StalwartCredentialSnapshot,
        record: StalwartCredentialRecord,
        inventory: StalwartReservedInventory,
    ): Boolean = matchesGenerationsExactly(
        snapshot = snapshot,
        expected = listOfNotNull(record.active, record.other),
        inventory = inventory,
    )

    private fun matchesRetiring(
        snapshot: StalwartCredentialSnapshot,
        record: StalwartCredentialRecord,
        inventory: StalwartReservedInventory,
    ): Boolean {
        val successor = record.active ?: return false
        val old = record.other ?: return false
        if (successor.generation <= old.generation) return false
        return matchesExactly(snapshot, record, inventory) ||
            matchesGenerationsExactly(
                snapshot = snapshot,
                expected = listOf(successor),
                inventory = inventory,
            )
    }

    private fun matchesGenerationsExactly(
        snapshot: StalwartCredentialSnapshot,
        expected: List<CredentialGeneration>,
        inventory: StalwartReservedInventory,
    ): Boolean {
        if (expected.size != inventory.reserved.size) return false
        val remoteById = inventory.reserved.associateBy { it.credentialId }
        if (remoteById.size != inventory.reserved.size) return false
        return expected.all { local ->
            val remote = remoteById[local.credentialId] ?: return@all false
            if (remote.description != local.description) return@all false
            remote.identity == StalwartReservedCredentialIdentity.Exact(
                storeId = snapshot.storeId,
                generation = local.generation,
            )
        }
    }

    private suspend fun probeAuthenticated(
        account: StalwartMailAccount,
        generation: CredentialGeneration,
    ): Boolean {
        val copied = generation.secret.copyForUse()
        StalwartBorrowedSecret.takeOwnership(copied).use { borrowed ->
            return when (
                val result = probe.probe(
                    accountId = account.accountId,
                    address = account.address,
                    secret = borrowed,
                )
            ) {
                is StalwartCredentialProbeResult.Authenticated ->
                    result.capabilities.containsAll(
                        STALWART_REQUIRED_MAIL_CAPABILITIES,
                    )
                StalwartCredentialProbeResult.Rejected,
                StalwartCredentialProbeResult.Unavailable,
                -> false
            }
        }
    }

    private fun projection(
        account: StalwartMailAccount,
        state: StalwartMailAccessState,
    ): StalwartMailAccessProjection =
        if (account.accountId in protectedAccountIds) {
            StalwartMailAccessProjection.protected(state)
        } else {
            StalwartMailAccessProjection.ordinary(state)
        }

    private class EnrollmentLocalContext(
        val storeId: java.util.UUID,
        val expected: RecordStamp?,
        val maxLocalGeneration: Long,
    ) : AutoCloseable {
        override fun close() {
            expected?.close()
        }
    }

    private class LocalRecordContext(
        val stamp: RecordStamp?,
    ) : AutoCloseable {
        override fun close() {
            stamp?.close()
        }
    }

    private sealed interface RotationLocalRead {
        data class Available(
            val context: RotationLocalContext,
        ) : RotationLocalRead

        data object Invalid : RotationLocalRead

        data object StoreUnavailable : RotationLocalRead
    }

    private sealed interface RestartLocalRead {
        data class Available(
            val context: RestartLocalContext,
        ) : RestartLocalRead

        data object Invalid : RestartLocalRead

        data object StoreUnavailable : RestartLocalRead
    }

    private class RotationLocalContext(
        val storeId: java.util.UUID,
        val expected: RecordStamp,
        val old: GenerationMaterial,
    ) : AutoCloseable {
        override fun close() {
            expected.close()
            old.secret.close()
        }
    }

    private class RestartLocalContext(
        val expected: RecordStamp,
        val phase: CredentialPhase,
        val active: GenerationMaterial,
        val other: GenerationMaterial?,
    ) : AutoCloseable {
        override fun close() {
            expected.close()
            active.secret.close()
            other?.secret?.close()
        }
    }

    private class GenerationMaterial(
        val credentialId: String,
        val description: String,
        val generation: Long,
        val secret: StalwartBorrowedSecret,
    ) {
        val reserved = StalwartReservedCredential(
            credentialId = credentialId,
            description = description,
        )
    }

    private class RecordStamp(
        val accountId: String,
        val addressAtCapture: String,
        val phase: CredentialPhase,
        val active: GenerationStamp?,
        val other: GenerationStamp?,
    ) : AutoCloseable {
        override fun equals(other: Any?): Boolean =
            other is RecordStamp &&
                accountId == other.accountId &&
                addressAtCapture == other.addressAtCapture &&
                phase == other.phase &&
                active == other.active &&
                this.other == other.other

        override fun hashCode(): Int {
            var result = accountId.hashCode()
            result = 31 * result + addressAtCapture.hashCode()
            result = 31 * result + phase.hashCode()
            result = 31 * result + (active?.hashCode() ?: 0)
            return 31 * result + (other?.hashCode() ?: 0)
        }

        override fun close() {
            active?.close()
            other?.close()
        }

        override fun toString(): String = "RecordStamp(redacted)"
    }

    private class GenerationStamp(
        val credentialId: String,
        val description: String,
        val generation: Long,
        val secretFingerprint: SecretFingerprint,
    ) : AutoCloseable {
        override fun equals(other: Any?): Boolean =
            other is GenerationStamp &&
                credentialId == other.credentialId &&
                description == other.description &&
                generation == other.generation &&
                secretFingerprint == other.secretFingerprint

        override fun hashCode(): Int {
            var result = credentialId.hashCode()
            result = 31 * result + description.hashCode()
            result = 31 * result + generation.hashCode()
            return 31 * result + secretFingerprint.hashCode()
        }

        override fun close() {
            secretFingerprint.close()
        }

        override fun toString(): String = "GenerationStamp(redacted)"
    }

    private class SecretFingerprint private constructor(
        private val digest: ByteArray,
    ) : AutoCloseable {
        private var closed = false

        override fun equals(other: Any?): Boolean {
            if (other !is SecretFingerprint) return false
            if (this === other) {
                synchronized(this) {
                    check(!closed) { "Secret fingerprint is closed" }
                }
                return true
            }
            val left = copyDigest()
            val right = try {
                other.copyDigest()
            } catch (failure: Throwable) {
                left.fill(0)
                throw failure
            }
            return try {
                MessageDigest.isEqual(left, right)
            } finally {
                left.fill(0)
                right.fill(0)
            }
        }

        override fun hashCode(): Int {
            synchronized(this) {
                check(!closed) { "Secret fingerprint is closed" }
            }
            return 0
        }

        @Synchronized
        private fun copyDigest(): ByteArray {
            check(!closed) { "Secret fingerprint is closed" }
            return digest.copyOf()
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            digest.fill(0)
        }

        override fun toString(): String = "SecretFingerprint(redacted)"

        companion object {
            fun takeOwnership(digest: ByteArray): SecretFingerprint {
                require(digest.isNotEmpty()) {
                    digest.fill(0)
                    "Secret fingerprint is absent"
                }
                return SecretFingerprint(digest)
            }
        }
    }

    private enum class LocalCommitResult {
        Committed,
        TargetChanged,
        RevisionChanged,
        StoreUnavailable,
    }

    private companion object {
        const val MAX_LOCAL_COMMIT_ATTEMPTS = 3
    }
}
