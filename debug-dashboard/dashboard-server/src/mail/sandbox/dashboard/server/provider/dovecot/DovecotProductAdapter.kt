package mail.sandbox.dashboard.server.provider.dovecot

import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.time.Duration

internal enum class DovecotProtocol {
    Imap,
    Pop3,
    Smtp,
}

internal data class DovecotAccount(
    val address: String,
    val protocols: Set<DovecotProtocol>,
)

internal data class DovecotFolder(val name: String)

internal data class DovecotMailboxState(
    val uidValidity: Long,
) {
    init {
        require(uidValidity > 0) { "Dovecot UIDVALIDITY is invalid" }
    }

    fun encode(): String = uidValidity.toString()

    companion object {
        fun decode(value: String): DovecotMailboxState = DovecotMailboxState(
            uidValidity = value.toLongOrNull()
                ?: throw IllegalArgumentException("Dovecot mutation state is invalid"),
        )
    }
}

internal data class DovecotMessageSummary(
    val uid: Long,
    val mailboxState: DovecotMailboxState,
    val messageId: String,
    val subject: String,
    val from: String,
    val date: String,
    val flags: Set<String>,
)

internal class DovecotCommandException(message: String) : IllegalStateException(message)

internal class DovecotProductAdapter(
    private val accounts: DovecotAccountRegistry,
    private val runner: DovecotCommandRunner,
) {
    fun listAccounts(): List<DovecotAccount> = accounts.list()
        .sorted()
        .map(::account)

    fun plainPassword(address: String): String? =
        accounts.plainPassword(requireLocalAddress(address))

    fun createAccount(address: String, password: ByteArray): DovecotAccount {
        val validatedAddress = requireLocalAddress(address)
        requirePassword(password)
        accounts.create(validatedAddress, password) {
            verifyAccountPresent(validatedAddress)
        }
        return account(validatedAddress)
    }

    fun changePassword(address: String, password: ByteArray) {
        val validatedAddress = requireLocalAddress(address)
        requirePassword(password)
        accounts.changePassword(validatedAddress, password) {
            verifyAccountPresent(validatedAddress)
        }
    }

    fun deleteAccount(address: String) {
        val validatedAddress = requireLocalAddress(address)
        accounts.delete(validatedAddress) {
            verifyAccountAbsent(validatedAddress)
        }
    }

    fun saveRawEmail(address: String, mailbox: String, eml: ByteArray) {
        requireValidEml(eml)
        execute(
            doveadm(
                "save", "-u", requireLocalAddress(address), "-m", requireMailbox(mailbox),
            ),
            stdin = eml,
            maximumOutputBytes = COMMAND_OUTPUT_BYTES,
        )
    }

    private fun execute(
        argv: List<String>,
        stdin: ByteArray = ByteArray(0),
        maximumOutputBytes: Int = COMMAND_OUTPUT_BYTES,
    ): ByteArray {
        val result = runner.run(
            DovecotCommandRequest(
                argv = argv,
                stdin = stdin,
                timeout = COMMAND_TIMEOUT,
                maximumOutputBytes = maximumOutputBytes,
            ),
        )
        if (
            result.timedOut ||
            result.exitCode != 0 ||
            result.stdout.size > maximumOutputBytes ||
            result.stderr.size > maximumOutputBytes
        ) {
            val detail = if (result.timedOut) {
                "timed out"
            } else {
                result.stderr.decodeUtf8().trim().take(MAXIMUM_ERROR_CHARACTERS)
                    .ifEmpty { "exit ${result.exitCode}" }
            }
            throw DovecotCommandException("Dovecot command failed: $detail")
        }
        return result.stdout
    }

    private fun requireValidEml(eml: ByteArray) {
        require(eml.isNotEmpty() && eml.size <= MAXIMUM_EML_BYTES && 0.toByte() !in eml) {
            "EML content is invalid"
        }
        val text = eml.decodeUtf8()
        val normalized = text.replace("\r\n", "\n")
        val separator = normalized.indexOf("\n\n")
        require(separator > 0) { "EML headers are invalid" }
        val headers = linkedMapOf<String, MutableList<String>>()
        var currentName: String? = null
        normalized.substring(0, separator).lineSequence().forEach { line ->
            if (line.startsWith(' ') || line.startsWith('\t')) {
                val name = requireNotNull(currentName) { "EML headers are invalid" }
                val values = headers.getValue(name)
                values[values.lastIndex] = values.last() + " " + line.trim()
            } else {
                val delimiter = line.indexOf(':')
                require(delimiter > 0) { "EML headers are invalid" }
                val name = line.substring(0, delimiter).lowercase()
                val value = line.substring(delimiter + 1).trim()
                require(value.isNotEmpty()) { "EML headers are invalid" }
                headers.getOrPut(name, ::mutableListOf).add(value)
                currentName = name
            }
        }
        REQUIRED_EML_HEADERS.forEach { name ->
            require(headers[name]?.any(String::isNotEmpty) == true) { "EML is missing $name" }
        }
    }

    private fun requireLocalAddress(address: String): String {
        val canonical = try {
            requireCanonicalDovecotAddress(address)
        } catch (failure: DovecotUsersFileException) {
            throw IllegalArgumentException(failure.message, failure)
        }
        require(canonical.substringAfter('@') == LOCAL_DOMAIN) {
            "Dovecot account must use local.test"
        }
        return canonical
    }

    private fun requirePassword(password: ByteArray) {
        require(
            password.size in 1..MAXIMUM_PASSWORD_BYTES &&
                password.none { it == 0.toByte() || it == '\r'.code.toByte() || it == '\n'.code.toByte() },
        ) {
            "Dovecot password is invalid"
        }
    }

    private fun requireMailbox(mailbox: String): String {
        require(
            mailbox.length in 1..MAXIMUM_MAILBOX_LENGTH &&
                (mailbox == "INBOX" || mailbox.startsWith("INBOX.")) &&
                mailbox == mailbox.trim() &&
                mailbox.none(Char::isISOControl),
        ) {
            "Dovecot mailbox is invalid"
        }
        val segments = mailbox.split('.')
        require(
            segments.first() == "INBOX" &&
                segments.drop(1).all { segment ->
                    segment.isNotEmpty() &&
                        segment.length <= MAXIMUM_MAILBOX_SEGMENT_LENGTH &&
                        segment.all { it.isLetterOrDigit() || it == ' ' || it == '-' || it == '_' }
                },
        ) {
            "Dovecot mailbox is invalid"
        }
        return mailbox
    }

    private fun doveadm(vararg arguments: String): List<String> = DOVEADM_PREFIX + arguments

    private fun verifyAccountPresent(address: String) {
        execute(doveadm("user", address))
    }

    private fun verifyAccountAbsent(address: String) {
        val result = runner.run(
            DovecotCommandRequest(
                argv = doveadm("user", address),
                timeout = COMMAND_TIMEOUT,
                maximumOutputBytes = COMMAND_OUTPUT_BYTES,
            ),
        )
        if (result.timedOut || result.exitCode != DOVEADM_NO_SUCH_USER) {
            throw DovecotCommandException("Dovecot did not confirm account removal")
        }
    }

    private fun account(address: String): DovecotAccount =
        DovecotAccount(
            address,
            setOf(DovecotProtocol.Imap, DovecotProtocol.Pop3, DovecotProtocol.Smtp),
        )

    companion object {
        fun production(repositoryRoot: Path = discoverRepositoryRoot()): DovecotProductAdapter =
            using(repositoryRoot)

        fun dashboard(repositoryRoot: Path = discoverRepositoryRoot()): DovecotProductAdapter =
            using(repositoryRoot)

        private fun using(repositoryRoot: Path): DovecotProductAdapter {
            val root = repositoryRoot.toAbsolutePath().normalize()
            require(
                root == repositoryRoot &&
                    !Files.isSymbolicLink(root) &&
                    Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) &&
                    Files.isRegularFile(
                        root.resolve("docker-compose.yml"),
                        LinkOption.NOFOLLOW_LINKS,
                    ),
            ) {
                "Dovecot repository root is invalid"
            }
            return DovecotProductAdapter(
                accounts = UsersFileDovecotAccountRegistry.production(root),
                runner = JvmDovecotCommandRunner(root),
            )
        }

        private fun discoverRepositoryRoot(): Path {
            var candidate = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
            repeat(MAXIMUM_ROOT_SEARCH_DEPTH) {
                if (Files.isRegularFile(
                        candidate.resolve("docker-compose.yml"),
                        LinkOption.NOFOLLOW_LINKS,
                    ) && Files.isDirectory(
                        candidate.resolve("debug-dashboard"),
                        LinkOption.NOFOLLOW_LINKS,
                    )
                ) {
                    return candidate
                }
                candidate = candidate.parent
                    ?: throw IllegalStateException("Could not locate the mail sandbox repository")
            }
            throw IllegalStateException("Could not locate the mail sandbox repository")
        }

        private val DOVEADM_PREFIX = listOf(
            "docker", "compose", "exec", "-T", "dovecot", "doveadm",
        )
        private val COMMAND_TIMEOUT: Duration = Duration.ofSeconds(30)
        private const val LOCAL_DOMAIN = "local.test"
        private const val MAXIMUM_MAILBOX_LENGTH = 255
        private const val MAXIMUM_MAILBOX_SEGMENT_LENGTH = 64
        private const val MAXIMUM_PASSWORD_BYTES = 4 * 1024
        private const val MAXIMUM_EML_BYTES = 5 * 1024 * 1024
        private const val COMMAND_OUTPUT_BYTES = 256 * 1024
        private const val MAXIMUM_ERROR_CHARACTERS = 512
        private const val MAXIMUM_ROOT_SEARCH_DEPTH = 4
        private const val DOVEADM_NO_SUCH_USER = 67
        private val REQUIRED_EML_HEADERS = setOf(
            "from", "to", "date", "subject", "message-id",
        )
    }
}

private fun ByteArray.decodeUtf8(): String = StandardCharsets.UTF_8.newDecoder()
    .onMalformedInput(CodingErrorAction.REPORT)
    .onUnmappableCharacter(CodingErrorAction.REPORT)
    .decode(java.nio.ByteBuffer.wrap(this))
    .toString()
