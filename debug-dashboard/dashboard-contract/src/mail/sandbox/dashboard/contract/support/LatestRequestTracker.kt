package mail.sandbox.dashboard.contract.support

/** Keeps asynchronous results tied to the selection that started them. */
class LatestRequestTracker<Key : Any> {
    private var generation = 0L
    private var activeKey: Key? = null

    fun begin(key: Key): Long {
        activeKey = key
        return ++generation
    }

    fun isCurrent(token: Long, key: Key): Boolean =
        token == generation && activeKey == key

    fun invalidate() {
        activeKey = null
        generation++
    }
}
