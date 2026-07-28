package mail.sandbox.dashboard.server.provider.stalwart.credential

import java.util.UUID

internal const val STALWART_RESERVED_DESCRIPTION_PREFIX =
    "mail-sandbox/debug-dashboard/"

internal data class StalwartReservedCredential(
    val credentialId: String,
    val description: String,
) {
    init {
        require(credentialId.isNotBlank()) { "Reserved credential ID is absent" }
        require(description.startsWith(STALWART_RESERVED_DESCRIPTION_PREFIX)) {
            "Credential description is outside the dashboard reservation"
        }
    }

    val identity: StalwartReservedCredentialIdentity =
        parseReservedIdentity(description)
}

internal sealed interface StalwartReservedCredentialIdentity {
    data class Exact(
        val storeId: UUID,
        val generation: Long,
    ) : StalwartReservedCredentialIdentity

    data object Malformed : StalwartReservedCredentialIdentity
}

internal data class StalwartReservedInventory(
    val accountId: String,
    val reserved: List<StalwartReservedCredential>,
    val appPasswordCount: Int,
    val appPasswordLimit: Int?,
) {
    init {
        require(accountId.isNotBlank()) { "Reserved inventory Account ID is absent" }
        require(appPasswordCount >= reserved.size && appPasswordCount >= 0) {
            "AppPassword inventory count is invalid"
        }
        require(appPasswordLimit == null || appPasswordLimit >= appPasswordCount) {
            "AppPassword inventory limit is invalid"
        }
        require(reserved.map { it.credentialId }.toSet().size == reserved.size) {
            "Reserved inventory contains duplicate credential IDs"
        }
    }

    val quotaAvailable: Boolean
        get() = appPasswordLimit == null || appPasswordCount < appPasswordLimit
}

internal data class StalwartGlobalReservedAccount(
    val accountId: String,
    val protectedIdentity: Boolean,
    val reserved: List<StalwartReservedCredential>,
) {
    init {
        require(accountId.isNotBlank()) { "Global inventory Account ID is absent" }
        require(reserved.map { it.credentialId }.toSet().size == reserved.size) {
            "Global reserved inventory contains duplicate credential IDs"
        }
    }
}

internal data class StalwartGlobalReservedInventory(
    val accounts: List<StalwartGlobalReservedAccount>,
) {
    init {
        require(accounts.map { it.accountId }.toSet().size == accounts.size) {
            "Global reserved inventory contains duplicate Accounts"
        }
    }

    val reserved: List<Pair<String, StalwartReservedCredential>>
        get() = accounts.flatMap { account ->
            account.reserved.map { account.accountId to it }
        }
}

private fun parseReservedIdentity(
    description: String,
): StalwartReservedCredentialIdentity {
    val suffix = description.removePrefix(STALWART_RESERVED_DESCRIPTION_PREFIX)
    if (suffix == description) return StalwartReservedCredentialIdentity.Malformed
    val segments = suffix.split('/')
    if (segments.size != 2) return StalwartReservedCredentialIdentity.Malformed
    val storeId = runCatching { UUID.fromString(segments[0]) }.getOrNull()
        ?: return StalwartReservedCredentialIdentity.Malformed
    val generation = segments[1].toLongOrNull()
        ?.takeIf { it > 0 }
        ?: return StalwartReservedCredentialIdentity.Malformed
    if ("$storeId/$generation" != suffix) {
        return StalwartReservedCredentialIdentity.Malformed
    }
    return StalwartReservedCredentialIdentity.Exact(storeId, generation)
}
