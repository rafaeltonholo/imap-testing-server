package mail.sandbox.dashboard.server.local

import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.AccountInfo
import mail.sandbox.dashboard.contract.CredentialReadiness
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

            val dovecotAccount = accountInfo(
                provider = Provider.DOVECOT,
                address = "alice@local.test",
                protocols = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP),
            )
            catalog.rememberVerifiedPassword(dovecotAccount, "rotated")
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
    fun versionOneCatalogMigratesToVersionTwoWithoutLosingProviderData() {
        val root = createTempDirectory("dashboard-account-catalog-v1")
        try {
            val path = root.resolve("accounts.json")
            Files.writeString(
                path,
                """
                {
                  "version": 1,
                  "accounts": [
                    {
                      "provider": "DOVECOT",
                      "address": "alice@local.test",
                      "password": "dove-password",
                      "protocols": ["IMAP"],
                      "providerAccountId": null,
                      "providerGeneration": null
                    },
                    {
                      "provider": "STALWART",
                      "address": "bob@local.test",
                      "password": "stalwart-password",
                      "protocols": ["JMAP", "SMTP"],
                      "providerAccountId": "account-42",
                      "providerGeneration": "${"a".repeat(64)}"
                    }
                  ]
                }
                """.trimIndent(),
            )

            val records = LocalAccountCatalog(path).list()

            assertEquals(
                listOf(
                    Provider.DOVECOT to "dove-password",
                    Provider.STALWART to "stalwart-password",
                ),
                records.map { it.provider to it.password },
            )
            assertEquals(listOf(MailProtocol.IMAP), records.first().protocols)
            assertEquals("account-42", records.last().providerAccountId)
            assertTrue("\"version\": 2" in path.readText())
            assertTrue("providerGeneration" !in path.readText())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun nullablePasswordCanBeRememberedOnlyThroughVerifiedCredentialApiAndForgotten() {
        val root = createTempDirectory("dashboard-account-catalog-null-password")
        try {
            val path = root.resolve("accounts.json")
            val catalog = LocalAccountCatalog(path)
            val live = accountInfo(
                provider = Provider.STALWART,
                address = "alice@local.test",
                protocols = listOf(MailProtocol.JMAP),
                providerAccountId = "account-42",
            )
            catalog.put(
                LocalAccountRecord(
                    provider = live.provider,
                    address = live.address,
                    password = null,
                    protocols = live.protocols,
                    providerAccountId = live.providerAccountId,
                ),
            )

            assertNull(catalog.findByIdentity(live)?.password)
            catalog.rememberVerifiedPassword(live, "verified-password")
            assertEquals("verified-password", catalog.findByIdentity(live)?.password)
            catalog.forgetPassword(live)
            assertNull(LocalAccountCatalog(path).findByIdentity(live)?.password)
            assertTrue("\"version\": 2" in path.readText())
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun stalwartProviderIdWinsAndDifferentIdNeverInheritsPasswordByAddress() {
        val root = createTempDirectory("dashboard-account-catalog-stalwart-identity")
        try {
            val catalog = LocalAccountCatalog(root.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = "old-password",
                    protocols = listOf(MailProtocol.JMAP),
                    providerAccountId = "old-id",
                ),
            )
            val recreated = accountInfo(
                provider = Provider.STALWART,
                address = "alice@local.test",
                protocols = listOf(MailProtocol.JMAP, MailProtocol.SMTP),
                providerAccountId = "new-id",
            )

            assertNull(catalog.findByIdentity(recreated))
            catalog.rememberVerifiedPassword(recreated, "new-password")
            assertEquals("new-password", catalog.findByIdentity(recreated)?.password)
            assertNull(catalog.findByProviderAccountId(Provider.STALWART, "old-id"))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun stalwartRemovalUsesTheExactProviderIdentity() {
        val root = createTempDirectory("dashboard-account-catalog-stalwart-remove")
        try {
            val catalog = LocalAccountCatalog(root.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = "current-password",
                    protocols = listOf(MailProtocol.JMAP),
                    providerAccountId = "current-id",
                ),
            )

            assertFalse(catalog.removeByProviderAccountId(Provider.STALWART, "stale-id"))
            assertEquals(
                "current-password",
                catalog.findByProviderAccountId(Provider.STALWART, "current-id")?.password,
            )
            assertTrue(catalog.removeByProviderAccountId(Provider.STALWART, "current-id"))
            assertNull(catalog.findByProviderAccountId(Provider.STALWART, "current-id"))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun stalwartLiveIdentityNeverInheritsAnIdLessLegacyPasswordByAddress() {
        val root = createTempDirectory("dashboard-account-catalog-stalwart-fallback")
        try {
            val catalog = LocalAccountCatalog(root.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.STALWART,
                    address = "alice@local.test",
                    password = "legacy-password",
                    protocols = listOf(MailProtocol.JMAP),
                    providerAccountId = null,
                ),
            )
            val live = accountInfo(
                provider = Provider.STALWART,
                address = "alice@local.test",
                protocols = listOf(MailProtocol.JMAP),
                providerAccountId = "live-id",
            )

            assertNull(catalog.findByIdentity(live))
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
    fun cachedProviderRecordsRemainAvailableForExplicitStaleProjection() {
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

            assertEquals(
                listOf(
                    Provider.STALWART to "current@local.test",
                    Provider.DOVECOT to "dove@local.test",
                    Provider.STALWART to "stale@local.test",
                ),
                catalog.list().map { it.provider to it.address },
            )
        } finally {
            root.toFile().deleteRecursively()
        }
    }


    private fun accountInfo(
        provider: Provider,
        address: String,
        protocols: List<MailProtocol>,
        providerAccountId: String? = null,
    ): AccountInfo = AccountInfo(
        address = address,
        provider = provider,
        protocols = protocols,
        credentialReadiness = CredentialReadiness.PASSWORD_REQUIRED,
        providerAccountId = providerAccountId,
    )
}
