package mail.sandbox.dashboard.contract

import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals

class ContractSerializationTest {
    private val json = Json

    @Test
    fun gateProbeUsesExactJsonFieldsAndRoundTrips() {
        val probe = GateProbe(message = "ready", sequence = 41L)
        val encoded = json.encodeToString(probe)

        val expected = buildJsonObject {
            put("message", "ready")
            put("sequence", 41L)
        }

        assertEquals(expected, json.parseToJsonElement(encoded))
        assertEquals(probe, json.decodeFromString<GateProbe>(encoded))
    }

    @Test
    fun gateEventUsesExactJsonFieldsAndRoundTrips() {
        val event = GateEvent(
            id = 42L,
            kind = "probe.received",
            payload = GateProbe(message = "ready", sequence = 41L),
        )
        val encoded = json.encodeToString(event)

        val expected = buildJsonObject {
            put("id", 42L)
            put("kind", "probe.received")
            put(
                "payload",
                buildJsonObject {
                    put("message", "ready")
                    put("sequence", 41L)
                },
            )
        }

        assertEquals(expected, json.parseToJsonElement(encoded))
        assertEquals(event, json.decodeFromString<GateEvent>(encoded))
    }

    @Test
    fun gateRoutesUseVersionedApiPaths() {
        assertEquals("/api/v1/gate/probe", Routes.GATE_PROBE)
        assertEquals("/api/v1/gate/events", Routes.GATE_EVENTS)
    }
}
