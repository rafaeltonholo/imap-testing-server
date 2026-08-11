package mail.sandbox.dashboard.server.provider.dovecot

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Path

internal interface DovecotAccountRegistry {
    fun list(): List<String>

    /** Returns the active ordinary-account password only when the authority uses `{PLAIN}`. */
    fun plainPassword(address: String): String? = null

    fun create(address: String, password: ByteArray, verifyProjection: () -> Unit)

    fun changePassword(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    )

    fun delete(address: String, verifyProjection: () -> Unit)
}

/** Adapts dashboard account operations directly to the shared `config/users` authority. */
internal class UsersFileDovecotAccountRegistry(
    private val file: DovecotUsersFile,
) : DovecotAccountRegistry {
    override fun list(): List<String> = file.list().map(DovecotUserRecord::address)

    override fun plainPassword(address: String): String? = file.list()
        .firstOrNull { record -> record.address == address }
        ?.plainPasswordOrNull()

    override fun create(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        withUtf8Password(password) { decoded ->
            file.create(address, decoded, verifyProjection)
        }
    }

    override fun changePassword(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        withUtf8Password(password) { decoded ->
            file.changePassword(address, decoded, verifyProjection)
        }
    }

    override fun delete(address: String, verifyProjection: () -> Unit) {
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
