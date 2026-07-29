package mail.sandbox.dashboard.server.gate.dovecot

internal object EligibilityAddress {
    private const val MAX_ADDRESS_LENGTH = 254
    private const val MAX_LOCAL_PART_LENGTH = 64
    private const val MAX_DOMAIN_LENGTH = 253
    private val localPartPattern = Regex("[a-z0-9](?:[a-z0-9._+%-]{0,62}[a-z0-9])?")
    private val domainLabelPattern = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

    fun requireCanonical(address: String): String {
        require(address.isNotEmpty() && address.length <= MAX_ADDRESS_LENGTH) {
            "Eligibility address is invalid"
        }
        require(address.all { character -> character.code in 0x21..0x7e }) {
            "Eligibility address is invalid"
        }
        require(address == address.lowercase()) {
            "Eligibility address is invalid"
        }
        require(address.count { it == '@' } == 1) {
            "Eligibility address is invalid"
        }
        require(
            ':' !in address &&
                ';' !in address &&
                '/' !in address &&
                '\\' !in address &&
                '"' !in address &&
                '(' !in address &&
                ')' !in address &&
                '<' !in address &&
                '>' !in address,
        ) {
            "Eligibility address is invalid"
        }
        val at = address.indexOf('@')
        val localPart = address.substring(0, at)
        val domain = address.substring(at + 1)
        require(
            localPart.length in 1..MAX_LOCAL_PART_LENGTH &&
                localPartPattern.matches(localPart) &&
                !localPart.contains(".."),
        ) {
            "Eligibility address is invalid"
        }
        require(domain.length in 1..MAX_DOMAIN_LENGTH) {
            "Eligibility address is invalid"
        }
        val labels = domain.split('.')
        require(
            labels.isNotEmpty() &&
                labels.all { label -> domainLabelPattern.matches(label) },
        ) {
            "Eligibility address is invalid"
        }
        return address
    }
}

internal class EligibilityEntry private constructor(
    val address: String,
    private val providerHash: String,
) {
    fun render(): String = "$address:$providerHash"

    internal fun withHash(hash: String): EligibilityEntry = create(address, hash)

    override fun toString(): String =
        "EligibilityEntry(address=$address, providerHash=redacted)"

    companion object {
        private const val HASH_PREFIX = "{ARGON2ID}"
        private const val MAX_HASH_LENGTH = 4 * 1024

        fun create(
            address: String,
            providerHash: String,
        ): EligibilityEntry {
            val canonicalAddress = EligibilityAddress.requireCanonical(address)
            requireValidHash(providerHash)
            return EligibilityEntry(canonicalAddress, providerHash)
        }

        fun parse(line: String): EligibilityEntry {
            require(line.count { it == ':' } == 1) {
                "Eligibility entry is invalid"
            }
            val delimiter = line.indexOf(':')
            require(delimiter > 0 && delimiter < line.lastIndex) {
                "Eligibility entry is invalid"
            }
            return create(
                address = line.substring(0, delimiter),
                providerHash = line.substring(delimiter + 1),
            )
        }

        fun requireValidHash(providerHash: String): String {
            require(
                providerHash.length > HASH_PREFIX.length &&
                    providerHash.length <= MAX_HASH_LENGTH &&
                    providerHash.startsWith(HASH_PREFIX),
            ) {
                "Eligibility provider hash is invalid"
            }
            require(
                providerHash.all { character ->
                    character.code in 0x21..0x7e && character != ':'
                },
            ) {
                "Eligibility provider hash is invalid"
            }
            val encoded = providerHash.removePrefix(HASH_PREFIX)
            val segments = encoded.split('$')
            require(
                segments.size == ARGON2_SEGMENT_COUNT &&
                    segments[0].isEmpty() &&
                    segments[1] == ARGON2_ALGORITHM &&
                    segments[2].length in 1..MAX_VERSION_SEGMENT_LENGTH &&
                    segments[3].length in 1..MAX_PARAMETER_SEGMENT_LENGTH &&
                    segments[4].length in 1..MAX_ENCODED_VALUE_SEGMENT_LENGTH &&
                    segments[5].length in 1..MAX_ENCODED_VALUE_SEGMENT_LENGTH,
            ) {
                "Eligibility provider hash is invalid"
            }
            return providerHash
        }

        private const val ARGON2_ALGORITHM = "argon2id"
        private const val ARGON2_SEGMENT_COUNT = 6
        private const val MAX_VERSION_SEGMENT_LENGTH = 32
        private const val MAX_PARAMETER_SEGMENT_LENGTH = 256
        private const val MAX_ENCODED_VALUE_SEGMENT_LENGTH = 1024
    }
}

internal class EligibilityDocument private constructor(
    private val lines: List<EligibilityLine>,
) {
    fun addresses(): List<String> = lines.mapNotNull { line ->
        (line as? EligibilityLine.Account)?.entry?.address
    }

    fun render(): String {
        if (lines.isEmpty()) return ""
        return lines.joinToString(separator = "\n", postfix = "\n") { it.render() }
    }

    fun add(entry: EligibilityEntry): EligibilityDocument {
        require(entry.address !in addresses()) {
            "Eligibility address already exists"
        }
        return EligibilityDocument(lines + EligibilityLine.Account(entry))
    }

    fun reset(entry: EligibilityEntry): EligibilityDocument {
        require(entry.address in addresses()) {
            "Eligibility address does not exist"
        }
        return EligibilityDocument(
            lines.map { line ->
                if (
                    line is EligibilityLine.Account &&
                    line.entry.address == entry.address
                ) {
                    EligibilityLine.Account(entry)
                } else {
                    line
                }
            },
        )
    }

    fun remove(address: String): EligibilityDocument {
        val canonicalAddress = EligibilityAddress.requireCanonical(address)
        require(canonicalAddress in addresses()) {
            "Eligibility address does not exist"
        }
        return EligibilityDocument(
            lines.filterNot { line ->
                line is EligibilityLine.Account &&
                    line.entry.address == canonicalAddress
            },
        )
    }

    override fun toString(): String =
        "EligibilityDocument(addresses=${addresses().size}, contents=redacted)"

    companion object {
        private const val MAX_FILE_CHARACTERS = 1024 * 1024

        fun empty(): EligibilityDocument = EligibilityDocument(emptyList())

        fun parse(contents: String): EligibilityDocument {
            require(contents.length <= MAX_FILE_CHARACTERS && '\r' !in contents) {
                "Eligibility file is invalid"
            }
            if (contents.isEmpty()) return empty()
            val rawLines = contents.split('\n').let { split ->
                if (contents.endsWith('\n')) split.dropLast(1) else split
            }
            val parsed = rawLines.map { raw ->
                when {
                    raw.isBlank() -> EligibilityLine.Blank(raw)
                    raw.trimStart().startsWith("#") -> EligibilityLine.Comment(raw)
                    else -> EligibilityLine.Account(EligibilityEntry.parse(raw))
                }
            }
            val addresses = parsed.mapNotNull { line ->
                (line as? EligibilityLine.Account)?.entry?.address
            }
            require(addresses.size == addresses.toSet().size) {
                "Eligibility file contains duplicate addresses"
            }
            return EligibilityDocument(parsed)
        }
    }
}

private sealed interface EligibilityLine {
    fun render(): String

    class Blank(
        private val contents: String,
    ) : EligibilityLine {
        override fun render(): String = contents
    }

    class Comment(
        private val contents: String,
    ) : EligibilityLine {
        override fun render(): String = contents
    }

    class Account(
        val entry: EligibilityEntry,
    ) : EligibilityLine {
        override fun render(): String = entry.render()
    }
}
