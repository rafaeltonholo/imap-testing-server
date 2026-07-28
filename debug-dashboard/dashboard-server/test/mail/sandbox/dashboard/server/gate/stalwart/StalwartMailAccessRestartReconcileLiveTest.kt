package mail.sandbox.dashboard.server.gate.stalwart

import kotlin.test.Test
import kotlinx.coroutines.runBlocking

class StalwartMailAccessRestartReconcileLiveTest {
    @Test
    fun reconcilesSelectedRestartPhaseWithoutCreate() = runBlocking {
        StalwartMailAccessLiveHarness.restartReconcile().use { harness ->
            harness.reconcileRestartPhase()
        }
    }
}
