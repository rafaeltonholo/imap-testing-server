package mail.sandbox.dashboard.web

import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.window.ComposeViewport
import kotlinx.browser.document
import org.jetbrains.compose.resources.configureWebResources

@OptIn(ExperimentalComposeUiApi::class)
fun main() {
    configureWebResources {
        resourcePathMapping { "/assets/$it" }
    }

    val mountTarget = requireNotNull(document.getElementById("dashboard-root")) {
        "Missing dashboard-root mount target"
    }
    ComposeViewport(mountTarget) {
        DashboardApp()
    }
}
