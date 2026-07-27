package mail.sandbox.dashboard.server.gate

import mail.sandbox.dashboard.contract.GateEvent
import mail.sandbox.dashboard.contract.GateProbe

internal sealed interface GateEventBatch {
    data class Events(val events: List<GateEvent>) : GateEventBatch

    data class Resync(val event: GateEvent) : GateEventBatch
}

internal class GateEventSource {
    private val lock = Any()
    private val retained = ArrayDeque<GateEvent>()
    private var nextId = 1L
    private var forcedEvictionComplete = false

    init {
        append(count = 2)
    }

    fun open(lastEventId: String?): GateEventBatch = synchronized(lock) {
        if (lastEventId == null) {
            retained.clear()
            nextId = 1L
            forcedEvictionComplete = false
            append(count = 2)
            return@synchronized GateEventBatch.Events(retained.toList())
        }

        val cursor = lastEventId.toLongOrNull()
        if (cursor == null || cursor <= 0L) {
            return@synchronized resync()
        }

        val cursorIndex = retained.indexOfFirst { it.id == cursor }
        if (cursorIndex < 0) {
            return@synchronized resync()
        }

        val alreadyRetained = retained.drop(cursorIndex + 1)
        if (alreadyRetained.isNotEmpty()) {
            return@synchronized GateEventBatch.Events(alreadyRetained)
        }

        if (!forcedEvictionComplete && cursor == 2L) {
            val resumed = append(count = 2)
            append(count = 2)
            forcedEvictionComplete = true
            return@synchronized GateEventBatch.Events(resumed)
        }

        GateEventBatch.Events(emptyList())
    }

    private fun append(count: Int): List<GateEvent> = buildList {
        repeat(count) {
            val id = nextId++
            val event = GateEvent(
                id = id,
                kind = "sequence",
                payload = GateProbe(
                    message = "gate sequence $id",
                    sequence = id,
                ),
            )
            retained.addLast(event)
            while (retained.size > BUFFER_CAPACITY) {
                retained.removeFirst()
            }
            add(event)
        }
    }

    private fun resync(): GateEventBatch.Resync {
        val latest = retained.last()
        return GateEventBatch.Resync(
            event = latest.copy(
                kind = "resync",
                payload = latest.payload.copy(message = "cursor no longer retained"),
            ),
        )
    }

    private companion object {
        const val BUFFER_CAPACITY = 2
    }
}
