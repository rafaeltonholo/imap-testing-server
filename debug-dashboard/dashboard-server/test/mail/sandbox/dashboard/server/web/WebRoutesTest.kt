package mail.sandbox.dashboard.server.web

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import mail.sandbox.dashboard.server.configureDashboard

class WebRoutesTest {
    @Test
    fun exposesExactlyOneReflectiveKtorModuleEntryPoint() {
        val moduleFunctions = Class.forName("mail.sandbox.dashboard.server.ApplicationKt")
            .declaredMethods
            .filter { it.name == "module" }

        assertEquals(1, moduleFunctions.size)
        assertEquals(1, moduleFunctions.single().parameterCount)
    }

    @Test
    fun servesAuthoredHistoryHtmlWithOneNarrowImportMapAndModuleEntry() = withFixture { fixture ->
        val bundle = fixture.load()

        testApplication {
            application { configureDashboard(bundle) }

            val overview = client.get("/")
            val details = client.get("/gate/details")

            assertEquals(HttpStatusCode.OK, overview.status)
            assertEquals(HttpStatusCode.OK, details.status)
            assertEquals(overview.bodyAsText(), details.bodyAsText())
            assertTrue(overview.headers[HttpHeaders.ContentType].orEmpty().startsWith("text/html"))
            assertEquals("no-store", overview.headers[HttpHeaders.CacheControl])

            val html = overview.bodyAsText()
            assertTrue(html.contains("<meta charset=\"UTF-8\">"))
            assertTrue(html.contains("name=\"viewport\""))
            assertTrue(html.contains("id=\"dashboard-root\""))
            assertTrue(html.contains("<noscript>"))
            assertTrue(html.contains("\"@js-joda/core\": \"/assets/js-joda.esm.js\""))
            val importMapIndex = html.indexOf("<script type=\"importmap\">")
            val bootstrapTag =
                "<script src=\"/assets/browser-bootstrap.js\" " +
                    "data-dashboard-entry=\"/assets/gate.mjs\"></script>"
            val bootstrapIndex = html.indexOf(bootstrapTag)
            assertTrue(importMapIndex >= 0)
            assertTrue(bootstrapIndex > importMapIndex)
            assertEquals(1, Regex(Regex.escape(bootstrapTag)).findAll(html).count())
            assertEquals(1, Regex("""<script\s+type="importmap">""").findAll(html).count())
            assertEquals(0, Regex("""<script\s+type="module"""").findAll(html).count())
            assertEquals(2, Regex("""<script\b""").findAll(html).count())
            assertTrue(html.contains(":focus-visible"))
        }
    }

    @Test
    fun servesEveryValidatedAssetWithExplicitMimeAndRevalidatingCacheHeaders() = withFixture { fixture ->
        val bundle = fixture.load()

        testApplication {
            application { configureDashboard(bundle) }

            bundle.assetPaths.forEach { path ->
                val response = client.get(path)
                val expected = bundle.requireAsset(path)

                assertEquals(HttpStatusCode.OK, response.status, path)
                assertEquals(
                    expected.contentType,
                    response.headers[HttpHeaders.ContentType].orEmpty().substringBefore(';'),
                    path,
                )
                assertEquals(
                    "public, max-age=0, must-revalidate",
                    response.headers[HttpHeaders.CacheControl],
                    path,
                )
                assertEquals("\"${expected.sha256}\"", response.headers[HttpHeaders.ETag], path)
            }

            assertEquals(
                "text/javascript",
                client.get("/assets/js-joda.esm.js")
                    .headers[HttpHeaders.ContentType]
                    .orEmpty()
                    .substringBefore(';'),
            )
            assertEquals(
                "application/wasm",
                client.get("/assets/skiko.wasm")
                    .headers[HttpHeaders.ContentType]
                    .orEmpty()
                    .substringBefore(';'),
            )
            assertEquals(
                "text/plain",
                client.get(
                    "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/nested/text/readme.txt",
                ).headers[HttpHeaders.ContentType].orEmpty().substringBefore(';'),
            )
            assertEquals(
                "image/svg+xml",
                client.get(
                    "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/nested/images/proof.svg",
                ).headers[HttpHeaders.ContentType].orEmpty().substringBefore(';'),
            )
            assertEquals(
                "font/woff2",
                client.get(
                    "/assets/composeResources/$GENERATED_RESOURCE_PACKAGE/nested/fonts/proof.woff2",
                ).headers[HttpHeaders.ContentType].orEmpty().substringBefore(';'),
            )
        }
    }

    @Test
    fun returnsTheExactTypedGateProbeAndKeepsUnknownApiRoutesOutOfTheSpa() =
        withFixture { fixture ->
            val bundle = fixture.load()

            testApplication {
                application { configureDashboard(bundle) }

                val probe = client.get("/api/v1/gate/probe")
                assertEquals(HttpStatusCode.OK, probe.status)
                assertEquals("application/json", probe.headers[HttpHeaders.ContentType]
                    .orEmpty().substringBefore(';'))
                assertEquals("""{"message":"ready","sequence":1}""", probe.bodyAsText())

                val missingApi = client.get("/api/v1/not-a-route")
                assertEquals(HttpStatusCode.NotFound, missingApi.status)
                assertEquals(
                    "application/json",
                    missingApi.headers[HttpHeaders.ContentType].orEmpty().substringBefore(';'),
                )
                assertEquals("""{"error":"not_found"}""", missingApi.bodyAsText())
                assertFalse(missingApi.bodyAsText().contains("<html"))

                val missingAsset = client.get("/assets/not-in-the-manifest.mjs")
                assertEquals(HttpStatusCode.NotFound, missingAsset.status)
            }
        }
}
