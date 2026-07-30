package mail.sandbox.dashboard.server.gate.dovecot

internal data class DovecotOperatorRotationIntent(
    val old: DovecotOperatorId,
    val new: DovecotOperatorId,
) {
    init {
        check(
            old != new &&
                when (old) {
                    DovecotOperatorId.A -> new == DovecotOperatorId.B
                    DovecotOperatorId.B -> new == DovecotOperatorId.A
                },
        ) {
            "Dovecot operator rotation intent is invalid"
        }
    }
}

internal data class DovecotOperatorMaster(
    val id: DovecotOperatorId,
    val hash: String,
)

internal data class DovecotOperatorRotationProjection(
    val intent: DovecotOperatorRotationIntent,
    val active: DovecotOperatorId,
    val masterIds: List<DovecotOperatorId>,
    val rawSlots: Set<DovecotOperatorId>,
) {
    fun phase(): DovecotOperatorRotationPhase {
        check(active == intent.old || active == intent.new) {
            "Dovecot operator rotation active reference is invalid"
        }
        return if (active == intent.old) {
            check(
                intent.old in rawSlots &&
                    masterIds in listOf(
                        listOf(intent.old),
                        listOf(intent.old, intent.new),
                    ) &&
                    (
                        masterIds.size == 1 ||
                            intent.new in rawSlots
                        ),
            ) {
                "Dovecot operator pre-switch rotation state is invalid"
            }
            DovecotOperatorRotationPhase.Rollback(
                intent = intent,
                stagedRawPresent = intent.new in rawSlots,
            )
        } else {
            check(
                intent.new in rawSlots &&
                    masterIds in listOf(
                        listOf(intent.old, intent.new),
                        listOf(intent.new),
                    ) &&
                    (
                        masterIds.size == 1 ||
                            intent.old in rawSlots
                        ),
            ) {
                "Dovecot operator post-switch rotation state is invalid"
            }
            DovecotOperatorRotationPhase.Forward(
                intent = intent,
                oldRawPresent = intent.old in rawSlots,
            )
        }
    }
}

internal sealed interface DovecotOperatorRotationPhase {
    val intent: DovecotOperatorRotationIntent

    data class Rollback(
        override val intent: DovecotOperatorRotationIntent,
        val stagedRawPresent: Boolean,
    ) : DovecotOperatorRotationPhase

    data class Forward(
        override val intent: DovecotOperatorRotationIntent,
        val oldRawPresent: Boolean,
    ) : DovecotOperatorRotationPhase
}

internal object DovecotOperatorRawSlotPair {
    fun requireDistinct(
        readFirst: () -> ByteArray,
        readSecond: () -> ByteArray,
    ) {
        val first = readFirst()
        try {
            val second = readSecond()
            try {
                check(!first.contentEquals(second)) {
                    "Dovecot operator rotation credentials are duplicated"
                }
            } finally {
                second.fill(0)
            }
        } finally {
            first.fill(0)
        }
    }
}
