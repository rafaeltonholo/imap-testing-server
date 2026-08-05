package mail.sandbox.dashboard.server.local

import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.Provider

class LocalAccountCatalogTest {
    @Test
    fun storesListsUpdatesAndRemovesLocalProviderCredentials() {
        val root = createTempDirectory("dashboard-account-catalog")
        try {
            val path = root.resolve("accounts.json")
            val catalog = LocalAccountCatalog(path)

            assertEquals(emptyList(), catalog.list())
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.DOVECOT,
                    address = "alice@local.test",
                    password = "first",
                    protocols = listOf(MailProtocol.IMAP, MailProtocol.SMTP),
                ),
            )
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = "second",
                    protocols = listOf(MailProtocol.JMAP),
                    providerAccountId = "account-42",
                ),
            )

            assertEquals(
                listOf(Provider.DOVECOT, Provider.STALWART),
                catalog.list().map(LocalAccountRecord::provider),
            )
            assertEquals(
                "second",
                catalog.require(Provider.STALWART, "alice@local.test").password,
            )
            assertEquals(
                "alice@local.test",
                catalog.findByProviderAccountId(Provider.STALWART, "account-42")?.address,
            )

            catalog.changePassword(Provider.DOVECOT, "alice@local.test", "rotated")
            assertEquals(
                "rotated",
                LocalAccountCatalog(path)
                    .require(Provider.DOVECOT, "alice@local.test")
                    .password,
            )

            catalog.remove(Provider.STALWART, "alice@local.test")
            assertNull(catalog.find(Provider.STALWART, "alice@local.test"))
            assertEquals(1, catalog.list().size)
            assertTrue(path.readText().endsWith("\n"))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun rejectsUnsupportedProviderProtocolCombinationsAndUnsafeAddresses() {
        val root = createTempDirectory("dashboard-account-catalog-invalid")
        try {
            val catalog = LocalAccountCatalog(root.resolve("accounts.json"))

            assertFailsWith<IllegalArgumentException> {
                catalog.put(
                    LocalAccountRecord(
                        provider = Provider.DOVECOT,
                        address = "Alice@example.com",
                        password = "password",
                        protocols = listOf(MailProtocol.JMAP),
                    ),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                catalog.put(
                    LocalAccountRecord(
                        provider = Provider.STALWART,
                        address = "alice@local.test",
                        password = "",
                        protocols = listOf(MailProtocol.IMAP),
                    ),
                )
            }
            assertTrue(Files.notExists(root.resolve("accounts.json")))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun malformedCatalogFailsClearlyInsteadOfSilentlyDroppingAccounts() {
        val root = createTempDirectory("dashboard-account-catalog-malformed")
        try {
            val path = root.resolve("accounts.json")
            Files.writeString(path, "not json")

            assertFailsWith<IllegalStateException> {
                LocalAccountCatalog(path).list()
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun retainingProviderAccountIdsDropsOnlyStaleStalwartCredentials() {
        val root = createTempDirectory("dashboard-account-catalog-reconcile")
        try {
            val catalog = LocalAccountCatalog(root.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    Provider.DOVECOT,
                    "dove@local.test",
                    "dove-password",
                    listOf(MailProtocol.IMAP),
                ),
            )
            catalog.put(
                LocalAccountRecord(
                    Provider.STALWART,
                    "current@local.test",
                    "current-password",
                    listOf(MailProtocol.JMAP),
                    "current-id",
                ),
            )
            catalog.put(
                LocalAccountRecord(
                    Provider.STALWART,
                    "stale@local.test",
                    "stale-password",
                    listOf(MailProtocol.JMAP),
                    "old-id",
                ),
            )

            catalog.retainProviderAccountIds(Provider.STALWART, setOf("current-id"))

            assertEquals(
                listOf(
                    Provider.STALWART to "current@local.test",
                    Provider.DOVECOT to "dove@local.test",
                ),
                catalog.list().map { it.provider to it.address },
            )
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
