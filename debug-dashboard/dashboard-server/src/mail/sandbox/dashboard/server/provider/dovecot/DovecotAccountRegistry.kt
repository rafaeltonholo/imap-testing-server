package mail.sandbox.dashboard.server.provider.dovecot

import mail.sandbox.dashboard.server.gate.dovecot.DovecotPasswordHasher
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityFile
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityPassword
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityPasswordHasher
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityPaths

internal interface DovecotAccountRegistry {
    fun list(): List<String>

    fun create(address: String, password: ByteArray)

    fun changePassword(address: String, password: ByteArray)

    fun delete(address: String)
}

internal class EligibilityDovecotAccountRegistry(
    private val file: EligibilityFile,
    private val passwordHasher: EligibilityPasswordHasher,
) : DovecotAccountRegistry {
    override fun list(): List<String> = file.list()

    override fun create(address: String, password: ByteArray) {
        withHashedPassword(password) { hash -> file.add(address, hash) }
    }

    override fun changePassword(address: String, password: ByteArray) {
        withHashedPassword(password) { hash -> file.reset(address, hash) }
    }

    override fun delete(address: String) {
        file.remove(address)
    }

    private fun <T> withHashedPassword(
        password: ByteArray,
        block: (String) -> T,
    ): T {
        val ownedCopy = password.copyOf()
        return EligibilityPassword.takeOwnership(ownedCopy).use { secret ->
            block(passwordHasher.hash(secret))
        }
    }

    companion object {
        fun production(paths: EligibilityPaths = EligibilityPaths.production()):
            EligibilityDovecotAccountRegistry = EligibilityDovecotAccountRegistry(
                file = EligibilityFile(paths),
                passwordHasher = DovecotPasswordHasher(paths.repositoryRoot),
            )
    }
}
