package mail.sandbox.dashboard.server.gate.stalwart

import kotlin.test.Test
import kotlinx.coroutines.runBlocking

class StalwartMailAccessRestartPrepareLiveTest {
    @Test
    fun persistsSelectedRestartPhase() = runBlocking {
        StalwartMailAccessLiveHarness.restartPrepare().use { harness ->
            harness.prepareRestartPhase()
        }
    }
}
