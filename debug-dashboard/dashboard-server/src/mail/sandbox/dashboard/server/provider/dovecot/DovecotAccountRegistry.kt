package mail.sandbox.dashboard.server.provider.dovecot

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Path

internal interface DovecotAccountRegistry {
    fun list(): List<String>

    fun create(address: String, password: ByteArray)

    fun createVerified(address: String, password: ByteArray, verifyProjection: () -> Unit) {
        create(address, password)
        verifyProjection()
    }

    fun changePassword(address: String, password: ByteArray)

    fun changePasswordVerified(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        changePassword(address, password)
        verifyProjection()
    }

    fun delete(address: String)

    fun deleteVerified(address: String, verifyProjection: () -> Unit) {
        delete(address)
        verifyProjection()
    }
}

/** Adapts dashboard account operations directly to the shared `config/users` authority. */
internal class UsersFileDovecotAccountRegistry(
    private val file: DovecotUsersFile,
) : DovecotAccountRegistry {
    override fun list(): List<String> = file.list().map(DovecotUserRecord::address)

    override fun create(address: String, password: ByteArray) {
        withUtf8Password(password) { decoded -> file.create(address, decoded) }
    }

    override fun createVerified(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        withUtf8Password(password) { decoded ->
            file.create(address, decoded, verifyProjection)
        }
    }

    override fun changePassword(address: String, password: ByteArray) {
        withUtf8Password(password) { decoded -> file.changePassword(address, decoded) }
    }

    override fun changePasswordVerified(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        withUtf8Password(password) { decoded ->
            file.changePassword(address, decoded, verifyProjection)
        }
    }

    override fun delete(address: String) {
        file.delete(address)
    }

    override fun deleteVerified(address: String, verifyProjection: () -> Unit) {
        file.delete(address, verifyProjection)
    }

    private fun <T> withUtf8Password(password: ByteArray, block: (String) -> T): T {
        val owned = password.copyOf()
        return try {
            val decoded = try {
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(owned))
                    .toString()
            } catch (failure: Exception) {
                throw DovecotUsersFileException("Dovecot password is not valid UTF-8", failure)
            }
            block(decoded)
        } finally {
            owned.fill(0)
        }
    }

    companion object {
        fun production(repositoryRoot: Path): UsersFileDovecotAccountRegistry =
            UsersFileDovecotAccountRegistry(
                DovecotUsersFile(repositoryRoot.resolve("config/users")),
            )
    }
}
