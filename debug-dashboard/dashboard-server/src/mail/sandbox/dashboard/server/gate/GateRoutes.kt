package mail.sandbox.dashboard.server.gate

import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mail.sandbox.dashboard.contract.GateProbe
import mail.sandbox.dashboard.contract.Routes

fun Route.gateRoutes() {
    get(Routes.GATE_PROBE) {
        call.respondText(
            text = Json.encodeToString(GateProbe(message = "ready", sequence = 1L)),
            contentType = ContentType.Application.Json,
        )
    }

    get("/api/v1/{path...}") {
        call.respondText(
            text = """{"error":"not_found"}""",
            contentType = ContentType.Application.Json,
            status = HttpStatusCode.NotFound,
        )
    }
}
