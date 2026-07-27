package mail.sandbox.dashboard.server.gate

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.response.respondTextWriter
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mail.sandbox.dashboard.contract.GateEvent
import mail.sandbox.dashboard.contract.GateProbe
import mail.sandbox.dashboard.contract.Routes

internal fun Route.gateRoutes(eventSource: GateEventSource = GateEventSource()) {
    get(Routes.GATE_PROBE) {
        call.respondText(
            text = Json.encodeToString(GateProbe(message = "ready", sequence = 1L)),
            contentType = ContentType.Application.Json,
        )
    }

    get(Routes.GATE_EVENTS) {
        val batch = eventSource.open(call.request.headers[HttpHeaders.LastEventID])
        call.response.header(HttpHeaders.CacheControl, "no-cache")
        call.respondTextWriter(contentType = ContentType.Text.EventStream) {
            when (batch) {
                is GateEventBatch.Events -> batch.events.forEach { event ->
                    writeEvent(event = event, type = null)
                }

                is GateEventBatch.Resync -> writeEvent(
                    event = batch.event,
                    type = "resync",
                )
            }
        }
    }

    get("/api/v1/{path...}") {
        call.respondText(
            text = """{"error":"not_found"}""",
            contentType = ContentType.Application.Json,
            status = HttpStatusCode.NotFound,
        )
    }
}

private fun java.io.Writer.writeEvent(
    event: GateEvent,
    type: String?,
) {
    write("retry: 50\n")
    if (type != null) {
        write("event: $type\n")
    }
    write("id: ${event.id}\n")
    write("data: ${Json.encodeToString(event)}\n\n")
    flush()
}
