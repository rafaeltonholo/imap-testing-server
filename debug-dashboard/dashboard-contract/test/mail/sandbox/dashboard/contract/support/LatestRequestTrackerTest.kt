package mail.sandbox.dashboard.contract.support

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LatestRequestTrackerTest {
    @Test
    fun onlyTheNewestMatchingRequestRemainsCurrent() {
        val tracker = LatestRequestTracker<String>()

        val accountA = tracker.begin("account-a")
        assertTrue(tracker.isCurrent(accountA, "account-a"))

        val accountB = tracker.begin("account-b")
        assertFalse(tracker.isCurrent(accountA, "account-a"))
        assertFalse(tracker.isCurrent(accountB, "account-a"))
        assertTrue(tracker.isCurrent(accountB, "account-b"))

        tracker.invalidate()
        assertFalse(tracker.isCurrent(accountB, "account-b"))
    }
}
