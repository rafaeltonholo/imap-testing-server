package mail.sandbox.dashboard.server.local

import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.UUID
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityAddress

@Serializable
internal data class LocalAccountRecord(
    val provider: Provider,
    val address: String,
    val password: String,
    val protocols: List<MailProtocol>,
    val providerAccountId: String? = null,
    val providerGeneration: String? = null,
)

@Serializable
private data class LocalAccountDocument(
    val version: Int = 1,
    val accounts: List<LocalAccountRecord> = emptyList(),
)

internal class LocalAccountCatalog(
    private val path: Path,
) {
    init {
        require(path.isAbsolute && path.normalize() == path) {
            "Account catalog path must be absolute"
        }
    }

    @Synchronized
    fun list(): List<LocalAccountRecord> = read().accounts.sortedWith(RECORD_ORDER)

    @Synchronized
    fun find(provider: Provider, address: String): LocalAccountRecord? {
        val canonical = requireAddress(address)
        return read().accounts.firstOrNull {
            it.provider == provider && it.address == canonical
        }
    }

    fun require(provider: Provider, address: String): LocalAccountRecord =
        find(provider, address)
            ?: throw NoSuchElementException("Account is not registered in the dashboard")

    @Synchronized
    fun findByProviderAccountId(
        provider: Provider,
        providerAccountId: String,
    ): LocalAccountRecord? = read().accounts.firstOrNull {
        it.provider == provider && it.providerAccountId == providerAccountId
    }

    @Synchronized
    fun put(record: LocalAccountRecord) {
        val validated = validated(record)
        val current = read().accounts
        val next = current.filterNot {
            it.provider == validated.provider && it.address == validated.address
        } + validated
        write(LocalAccountDocument(accounts = next.sortedWith(RECORD_ORDER)))
    }

    @Synchronized
    fun putIfAbsent(record: LocalAccountRecord): Boolean {
        val validated = validated(record)
        val current = read().accounts
        if (current.any {
                it.provider == validated.provider && it.address == validated.address
            }
        ) {
            return false
        }
        write(LocalAccountDocument(accounts = (current + validated).sortedWith(RECORD_ORDER)))
        return true
    }

    @Synchronized
    fun changePassword(provider: Provider, address: String, password: String) {
        val current = require(provider, address)
        put(current.copy(password = password))
    }

    @Synchronized
    fun remove(provider: Provider, address: String): Boolean {
        val canonical = requireAddress(address)
        val current = read().accounts
        val next = current.filterNot {
            it.provider == provider && it.address == canonical
        }
        if (next.size == current.size) return false
        write(LocalAccountDocument(accounts = next.sortedWith(RECORD_ORDER)))
        return true
    }

    @Synchronized
    fun retainProviderAccountIds(provider: Provider, activeIds: Set<String>) {
        require(provider == Provider.STALWART) {
            "Only Stalwart records use provider Account IDs"
        }
        require(activeIds.all(PROVIDER_ACCOUNT_ID::matches)) {
            "Active Stalwart Account IDs are invalid"
        }
        val current = read().accounts
        val next = current.filter { record ->
            record.provider != provider || record.providerAccountId in activeIds
        }
        if (next.size != current.size) {
            write(LocalAccountDocument(accounts = next.sortedWith(RECORD_ORDER)))
        }
    }

    private fun read(): LocalAccountDocument {
        if (Files.notExists(path)) return LocalAccountDocument()
        val document = try {
            JSON.decodeFromString<LocalAccountDocument>(Files.readString(path))
        } catch (failure: Exception) {
            throw IllegalStateException("Dashboard account catalog is malformed", failure)
        }
        check(document.version == 1) { "Dashboard account catalog version is unsupported" }
        val validated = document.accounts.map(::validated)
        check(
            validated.map { it.provider to it.address }.toSet().size == validated.size,
        ) {
            "Dashboard account catalog contains duplicate accounts"
        }
        return document.copy(accounts = validated)
    }

    private fun write(document: LocalAccountDocument) {
        val parent = requireNotNull(path.parent)
        Files.createDirectories(parent)
        val temporary = parent.resolve(".${path.fileName}.${UUID.randomUUID()}.tmp")
        try {
            Files.writeString(
                temporary,
                JSON.encodeToString(document) + "\n",
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE,
            )
            try {
                Files.move(
                    temporary,
                    path,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    /** Validates and canonicalizes a record without mutating the catalog. */
    internal fun validated(record: LocalAccountRecord): LocalAccountRecord {
        val address = requireAddress(record.address)
        require(record.password.isNotEmpty() && record.password.length <= 4_096) {
            "Account password is absent or too large"
        }
        require(record.password.none { it == '\u0000' || it == '\r' || it == '\n' }) {
            "Account password contains an unsupported delimiter"
        }
        val protocols = record.protocols.distinct()
        require(protocols.isNotEmpty()) { "At least one protocol is required" }
        val allowed = when (record.provider) {
            Provider.DOVECOT -> DOVECOT_PROTOCOLS
            Provider.STALWART -> STALWART_PROTOCOLS
        }
        require(protocols.all(allowed::contains)) {
            "Selected protocols are not supported by this provider"
        }
        when (record.provider) {
            Provider.DOVECOT -> require(record.providerAccountId == null) {
                "Dovecot records do not use a provider Account ID"
            }.also {
                require(record.providerGeneration == null) {
                    "Dovecot records do not use a provider generation"
                }
            }

            Provider.STALWART -> {
                record.providerAccountId?.let { accountId ->
                    require(PROVIDER_ACCOUNT_ID.matches(accountId)) {
                        "Stalwart Account ID is invalid"
                    }
                }
                record.providerGeneration?.let { generation ->
                    require(PROVIDER_GENERATION.matches(generation)) {
                        "Stalwart provider generation is invalid"
                    }
                }
            }
        }
        return record.copy(address = address, protocols = protocols)
    }

    private fun requireAddress(value: String): String {
        val canonical = EligibilityAddress.requireCanonical(value)
        require(canonical.substringAfter('@') == "local.test") {
            "Account address must be a canonical local.test address"
        }
        return canonical
    }

    companion object {
        private val JSON = Json {
            prettyPrint = true
            encodeDefaults = true
            ignoreUnknownKeys = false
        }
        private val PROVIDER_ACCOUNT_ID = Regex("[A-Za-z0-9_-]{1,255}")
        private val PROVIDER_GENERATION = Regex("[a-f0-9]{64}")
        private val DOVECOT_PROTOCOLS = setOf(
            MailProtocol.IMAP,
            MailProtocol.POP3,
            MailProtocol.SMTP,
        )
        private val STALWART_PROTOCOLS = setOf(MailProtocol.JMAP, MailProtocol.SMTP)
        private val RECORD_ORDER = compareBy<LocalAccountRecord>(
            LocalAccountRecord::address,
            { it.provider.ordinal },
        )

        fun production(repositoryRoot: Path): LocalAccountCatalog = LocalAccountCatalog(
            repositoryRoot.resolve("debug-dashboard/.runtime/dashboard/accounts.json")
                .toAbsolutePath()
                .normalize(),
        )
    }
}
