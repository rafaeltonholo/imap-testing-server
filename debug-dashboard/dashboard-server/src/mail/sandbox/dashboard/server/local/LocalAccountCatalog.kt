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
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.server.gate.dovecot.EligibilityAddress

private const val LOCAL_ACCOUNT_CATALOG_VERSION = 2

@Serializable
internal data class LocalAccountRecord(
    val provider: Provider,
    val address: String,
    val password: String?,
    val protocols: List<MailProtocol>,
    val providerAccountId: String? = null,
)

@Serializable
private data class LocalAccountDocument(
    val version: Int = LOCAL_ACCOUNT_CATALOG_VERSION,
    val accounts: List<LocalAccountRecord> = emptyList(),
)

@Serializable
private data class LegacyLocalAccountRecord(
    val provider: Provider,
    val address: String,
    val password: String,
    val protocols: List<MailProtocol>,
    val providerAccountId: String? = null,
    val providerGeneration: String? = null,
)

@Serializable
private data class LegacyLocalAccountDocument(
    val version: Int = 1,
    val accounts: List<LegacyLocalAccountRecord> = emptyList(),
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
    fun findByIdentity(account: AccountInfo): LocalAccountRecord? {
        val canonical = requireAddress(account.address)
        val records = read().accounts.filter { it.provider == account.provider }
        return when (account.provider) {
            Provider.DOVECOT -> records.firstOrNull { it.address == canonical }
            Provider.STALWART -> {
                val accountId = account.providerAccountId
                if (accountId != null) {
                    records.firstOrNull { it.providerAccountId == accountId }
                } else {
                    records.firstOrNull {
                        it.address == canonical && it.providerAccountId == null
                    }
                }
            }
        }
    }

    @Synchronized
    fun put(record: LocalAccountRecord) {
        val validated = validated(record)
        val current = read().accounts
        val next = current.filterNot { it.sameStoredIdentity(validated) } + validated
        write(LocalAccountDocument(accounts = next.sortedWith(RECORD_ORDER)))
    }

    @Synchronized
    fun putIfAbsent(record: LocalAccountRecord): Boolean {
        val validated = validated(record)
        val current = read().accounts
        if (current.any { it.sameStoredIdentity(validated) }) {
            return false
        }
        write(LocalAccountDocument(accounts = (current + validated).sortedWith(RECORD_ORDER)))
        return true
    }

    @Synchronized
    fun rememberVerifiedPassword(account: AccountInfo, password: String) {
        requirePassword(password)
        val current = findByIdentity(account)
        put(
            LocalAccountRecord(
                provider = account.provider,
                address = account.address,
                password = password,
                protocols = account.protocols,
                providerAccountId = account.providerAccountId,
            ).let { live ->
                if (current == null) live else live.copy(
                    providerAccountId = live.providerAccountId ?: current.providerAccountId,
                )
            },
        )
    }

    @Synchronized
    fun forgetPassword(account: AccountInfo): Boolean {
        val current = findByIdentity(account) ?: return false
        if (current.password == null) return false
        put(current.copy(password = null))
        return true
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
    fun removeByProviderAccountId(provider: Provider, providerAccountId: String): Boolean {
        require(provider == Provider.STALWART) {
            "Only Stalwart records use a provider Account ID"
        }
        require(PROVIDER_ACCOUNT_ID.matches(providerAccountId)) {
            "Stalwart Account ID is invalid"
        }
        val current = read().accounts
        val next = current.filterNot {
            it.provider == provider && it.providerAccountId == providerAccountId
        }
        if (next.size == current.size) return false
        write(LocalAccountDocument(accounts = next.sortedWith(RECORD_ORDER)))
        return true
    }

    private fun read(): LocalAccountDocument {
        if (Files.notExists(path)) return LocalAccountDocument()
        val encoded = Files.readString(path)
        val sourceVersion: Int
        val document = try {
            sourceVersion = JSON.parseToJsonElement(encoded)
                .jsonObject["version"]
                ?.jsonPrimitive
                ?.intOrNull
                ?: 1
            when (sourceVersion) {
                1 -> JSON.decodeFromString<LegacyLocalAccountDocument>(encoded).let { legacy ->
                    check(legacy.version == 1) {
                        "Dashboard account catalog version is unsupported"
                    }
                    LocalAccountDocument(
                        accounts = legacy.accounts.map { record ->
                            LocalAccountRecord(
                                provider = record.provider,
                                address = record.address,
                                password = record.password,
                                protocols = record.protocols,
                                providerAccountId = record.providerAccountId,
                            )
                        },
                    )
                }
                LOCAL_ACCOUNT_CATALOG_VERSION -> JSON.decodeFromString<LocalAccountDocument>(encoded)
                else -> error("Dashboard account catalog version is unsupported")
            }
        } catch (failure: Exception) {
            throw IllegalStateException("Dashboard account catalog is malformed", failure)
        }
        check(document.version == LOCAL_ACCOUNT_CATALOG_VERSION) {
            "Dashboard account catalog version is unsupported"
        }
        val validated = document.accounts.map(::validated)
        check(
            validated.map { it.provider to it.address }.toSet().size == validated.size,
        ) {
            "Dashboard account catalog contains duplicate accounts"
        }
        check(
            validated.filter { it.provider == Provider.STALWART }
                .mapNotNull(LocalAccountRecord::providerAccountId)
                .let { ids -> ids.toSet().size == ids.size },
        ) {
            "Dashboard account catalog contains duplicate provider Account IDs"
        }
        return document.copy(accounts = validated).also { migrated ->
            if (sourceVersion == 1) write(migrated)
        }
    }

    private fun write(document: LocalAccountDocument) {
        require(document.version == LOCAL_ACCOUNT_CATALOG_VERSION) {
            "Dashboard account catalog writes must use version $LOCAL_ACCOUNT_CATALOG_VERSION"
        }
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
        record.password?.let(::requirePassword)
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
            }

            Provider.STALWART -> {
                record.providerAccountId?.let { accountId ->
                    require(PROVIDER_ACCOUNT_ID.matches(accountId)) {
                        "Stalwart Account ID is invalid"
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

    private fun requirePassword(password: String) {
        require(password.isNotEmpty() && password.length <= MAX_PASSWORD_LENGTH) {
            "Account password is absent or too large"
        }
        require(password.none { it == '\u0000' || it == '\r' || it == '\n' }) {
            "Account password contains an unsupported delimiter"
        }
    }

    private fun LocalAccountRecord.sameStoredIdentity(other: LocalAccountRecord): Boolean =
        provider == other.provider && (
            address == other.address ||
                provider == Provider.STALWART &&
                providerAccountId != null &&
                providerAccountId == other.providerAccountId
            )

    companion object {
        private val JSON = Json {
            prettyPrint = true
            encodeDefaults = true
            ignoreUnknownKeys = false
        }
        private val PROVIDER_ACCOUNT_ID = Regex("[A-Za-z0-9_-]{1,255}")
        private const val MAX_PASSWORD_LENGTH = 4_096
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
