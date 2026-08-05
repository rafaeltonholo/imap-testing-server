package mail.sandbox.dashboard.server

import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStopped
import mail.sandbox.dashboard.server.api.DashboardBackend
import mail.sandbox.dashboard.server.api.UnavailableDashboardBackend
import mail.sandbox.dashboard.server.local.LocalDashboardBackend
import mail.sandbox.dashboard.server.web.WebAssetBundle

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    val backend = LocalDashboardBackend.production()
    monitor.subscribe(ApplicationStopped) {
        backend.close()
    }
    configureDashboard(WebAssetBundle.fromEnvironment(), backend)
}

fun Application.configureDashboard(
    webAssets: WebAssetBundle,
    dashboardBackend: DashboardBackend = UnavailableDashboardBackend,
) {
    configureRouting(webAssets, dashboardBackend)
}
