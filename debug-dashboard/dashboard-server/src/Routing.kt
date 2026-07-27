package mail.sandbox.dashboard.server

import io.ktor.server.application.Application
import io.ktor.server.routing.routing
import mail.sandbox.dashboard.server.gate.gateRoutes
import mail.sandbox.dashboard.server.web.WebAssetBundle
import mail.sandbox.dashboard.server.web.webRoutes

fun Application.configureRouting(webAssets: WebAssetBundle) {
    routing {
        gateRoutes()
        webRoutes(webAssets)
    }
}
