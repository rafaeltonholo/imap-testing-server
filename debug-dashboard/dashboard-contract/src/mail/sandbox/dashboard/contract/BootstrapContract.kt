package mail.sandbox.dashboard.contract

import kotlinx.serialization.Serializable

@Serializable
data class GateProbe(val message: String, val sequence: Long)
