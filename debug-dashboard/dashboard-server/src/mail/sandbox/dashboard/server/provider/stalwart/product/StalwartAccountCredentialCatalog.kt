package mail.sandbox.dashboard.server.provider.stalwart.product

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import mail.sandbox.dashboard.server.gate.stalwart.GateCredential

internal data class StalwartAccountLogin(
    val accountId: String,
    val address: String,
    val password: String,
)

internal interface StalwartAccountCredentialCatalog {
    suspend fun find(accountId: String): StalwartAccountLogin?

    suspend fun save(login: StalwartAccountLogin)

    suspend fun remove(accountId: String)
}

internal class InMemoryStalwartAccountCredentialCatalog :
    StalwartAccountCredentialCatalog {
    private val mutex = Mutex()
    private val logins = linkedMapOf<String, StalwartAccountLogin>()

    override suspend fun find(accountId: String): StalwartAccountLogin? =
        mutex.withLock { logins[accountId] }

    override suspend fun save(login: StalwartAccountLogin) {
        mutex.withLock { logins[login.accountId] = login }
    }

    override suspend fun remove(accountId: String) {
        mutex.withLock { logins.remove(accountId) }
    }
}

internal fun interface StalwartManagementCredentialProvider {
    /** Returns a fresh credential whose ownership transfers to the caller. */
    fun openCredential(): GateCredential
}
