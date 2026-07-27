package mail.sandbox.dashboard.server.web

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.withCharset
import io.ktor.server.request.path
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get

fun Route.webRoutes(bundle: WebAssetBundle) {
    fun Route.historyRoute(path: String) {
        get(path) {
            call.response.header(HttpHeaders.CacheControl, "no-store")
            call.respondText(
                text = bundle.html,
                contentType = ContentType.Text.Html.withCharset(Charsets.UTF_8),
            )
        }
    }

    historyRoute("/")
    historyRoute("/gate/details")

    get("/assets/{path...}") {
        val asset = bundle.asset(call.request.path())
        if (asset == null) {
            call.respond(HttpStatusCode.NotFound)
            return@get
        }
        call.response.header(
            HttpHeaders.CacheControl,
            "public, max-age=0, must-revalidate",
        )
        call.response.header(HttpHeaders.ETag, "\"${asset.sha256}\"")
        call.respondBytes(
            bytes = asset.bytes,
            contentType = ContentType.parse(asset.contentType),
        )
    }
}
