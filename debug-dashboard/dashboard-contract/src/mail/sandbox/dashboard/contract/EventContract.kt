package mail.sandbox.dashboard.contract

import kotlinx.serialization.Serializable

@Serializable
data class GateEvent(val id: Long, val kind: String, val payload: GateProbe)
