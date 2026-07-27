package mail.sandbox.dashboard.server.gate

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.Routes

class GateEventSourceTest {
    @Test
    fun resumesMonotonicallyThenReportsTheEvictedCursorAsStale() {
        val source = GateEventSource()

        val initial = assertIs<GateEventBatch.Events>(source.open(lastEventId = null))
        val resumed = assertIs<GateEventBatch.Events>(source.open(lastEventId = "2"))
        val stale = assertIs<GateEventBatch.Resync>(source.open(lastEventId = "4"))

        assertEquals(listOf(1L, 2L), initial.events.map { it.id })
        assertEquals(listOf(3L, 4L), resumed.events.map { it.id })
        assertTrue(resumed.events.zipWithNext().all { (left, right) -> left.id < right.id })
        assertEquals(6L, stale.event.id)
        assertEquals("resync", stale.event.kind)
        assertEquals(6L, stale.event.payload.sequence)
    }

    @Test
    fun invalidAndUnknownCursorsUseTheTypedResyncBranch() {
        listOf("", "not-a-number", "0", "9").forEach { cursor ->
            val source = GateEventSource()

            val result = assertIs<GateEventBatch.Resync>(source.open(cursor))

            assertEquals("resync", result.event.kind, cursor)
            assertEquals(2L, result.event.payload.sequence, cursor)
        }
    }

    @Test
    fun aNewBrowserPageWithoutACursorStartsAFreshDeterministicCycle() {
        val source = GateEventSource()
        source.open(lastEventId = null)
        source.open(lastEventId = "2")
        source.open(lastEventId = "4")

        val reloaded = assertIs<GateEventBatch.Events>(source.open(lastEventId = null))
        val resumed = assertIs<GateEventBatch.Events>(source.open(lastEventId = "2"))

        assertEquals(listOf(1L, 2L), reloaded.events.map { it.id })
        assertEquals(listOf(3L, 4L), resumed.events.map { it.id })
    }

    @Test
    fun endpointEmitsValidClosingEventStreamsAndHonorsBrowserLastEventId() =
        testApplication {
            val source = GateEventSource()
            application {
                routing {
                    gateRoutes(source)
                }
            }

            val first = client.get(Routes.GATE_EVENTS)
            assertEquals(HttpStatusCode.OK, first.status)
            assertEquals(
                ContentType.Text.EventStream.toString(),
                first.headers[HttpHeaders.ContentType]?.substringBefore(';'),
            )
            assertEquals("no-cache", first.headers[HttpHeaders.CacheControl])
            assertSequenceStream(first.bodyAsText(), listOf(1L, 2L))

            val resumed = client.get(Routes.GATE_EVENTS) {
                header(HttpHeaders.LastEventID, "2")
            }
            assertSequenceStream(resumed.bodyAsText(), listOf(3L, 4L))

            val stale = client.get(Routes.GATE_EVENTS) {
                header(HttpHeaders.LastEventID, "4")
            }.bodyAsText()
            assertTrue(stale.contains("event: resync\n"), stale)
            assertTrue(stale.contains("\"id\":6"), stale)
            assertTrue(stale.contains("\"kind\":\"resync\""), stale)
            assertTrue(stale.endsWith("\n\n"), stale)
        }

    private fun assertSequenceStream(body: String, expectedIds: List<Long>) {
        assertTrue(body.startsWith("retry: 50\n"), body)
        assertEquals(expectedIds, Regex("""(?m)^id: (\d+)$""")
            .findAll(body)
            .map { it.groupValues[1].toLong() }
            .toList())
        assertEquals(
            expectedIds,
            Regex(""""sequence":(\d+)""")
                .findAll(body)
                .map { it.groupValues[1].toLong() }
                .toList(),
        )
        assertTrue(body.endsWith("\n\n"), body)
    }
}
