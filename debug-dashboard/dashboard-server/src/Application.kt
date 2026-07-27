package mail.sandbox.dashboard.server

import io.ktor.server.application.Application
import mail.sandbox.dashboard.server.web.WebAssetBundle

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    configureDashboard(WebAssetBundle.fromEnvironment())
}

fun Application.configureDashboard(webAssets: WebAssetBundle) {
    configureRouting(webAssets)
}
