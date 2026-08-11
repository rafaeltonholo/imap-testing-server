package mail.sandbox.dashboard.server.local

import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.AdoptPasswordRequest
import mail.sandbox.dashboard.contract.AuthenticationProbeRequest
import mail.sandbox.dashboard.contract.AuthenticationProtocol
import mail.sandbox.dashboard.contract.CredentialReadiness
import mail.sandbox.dashboard.contract.CreateAccountRequest
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.MailProtocol
import mail.sandbox.dashboard.contract.MessageAction
import mail.sandbox.dashboard.contract.MessageDeliveryMode
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.MutateMessagesRequest
import mail.sandbox.dashboard.contract.Provider
import mail.sandbox.dashboard.server.provider.AccountCredentials
import mail.sandbox.dashboard.server.provider.AuthenticationOutcome
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationAttempt
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationConnector
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationMechanism
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProbe
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationProtocol
import mail.sandbox.dashboard.server.provider.ProviderAuthenticationTransportOutcome
import mail.sandbox.dashboard.server.provider.dovecot.DovecotAccountRegistry
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandRequest
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandResult
import mail.sandbox.dashboard.server.provider.dovecot.DovecotCommandRunner
import mail.sandbox.dashboard.server.provider.dovecot.DovecotFolder
import mail.sandbox.dashboard.server.provider.dovecot.DovecotImapClient
import mail.sandbox.dashboard.server.provider.dovecot.DovecotImapStoreFactory
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMailboxClient
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMailboxState
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMessageCommand
import mail.sandbox.dashboard.server.provider.dovecot.DovecotMessageSummary
import mail.sandbox.dashboard.server.provider.dovecot.DovecotProductAdapter

class DovecotDashboardProviderTest {
    @Test
    fun malformedPasswordCacheDegradesOnlyAccountsThatNeedItsFallback() = runBlocking {
        val directory = createTempDirectory("dovecot-readiness-cache-isolation").toRealPath()
        try {
            val catalogPath = directory.resolve("accounts.json")
            catalogPath.writeText("{")
            val mailbox = RecordingMailboxClient()
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MultipleAccountRegistry(
                        linkedMapOf(
                            "alice@local.test" to null,
                            "bob@local.test" to "bob-password",
                        ),
                    ),
                    QueueRunner(),
                ),
                catalog = LocalAccountCatalog(catalogPath),
                mailboxClient = mailbox,
            )

            val accounts = provider.listAccounts()

            assertEquals(
                listOf("alice@local.test", "bob@local.test"),
                accounts.map { it.address },
            )
            assertEquals(
                listOf(CredentialReadiness.PROVIDER_UNAVAILABLE, CredentialReadiness.READY),
                accounts.map { it.credentialReadiness },
            )
            assertTrue("catalog" in accounts.first().readinessMessage.orEmpty().lowercase())
            assertEquals(
                listOf(AccountCredentials("bob@local.test", "bob-password")),
                mailbox.probed,
            )
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun accountListingStopsProbingAfterProviderTransportBecomesUnavailable() = runBlocking {
        val directory = createTempDirectory("dovecot-readiness-bounded-probes").toRealPath()
        try {
            val mailbox = RecordingMailboxClient(
                probeOutcomes = listOf(AuthenticationOutcome.TimedOut("read timed out")),
            )
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MultipleAccountRegistry(
                        linkedMapOf(
                            "alice@local.test" to "alice-password",
                            "bob@local.test" to "bob-password",
                            "carol@local.test" to "carol-password",
                        ),
                    ),
                    QueueRunner(),
                ),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            val accounts = provider.listAccounts()

            assertEquals(3, accounts.size)
            assertTrue(accounts.all {
                it.credentialReadiness == CredentialReadiness.PROVIDER_UNAVAILABLE
            })
            assertEquals(1, mailbox.probed.size)
            assertTrue(accounts.drop(1).all {
                "skipped" in it.readinessMessage.orEmpty().lowercase()
            })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun accountListingMapsEveryOrdinaryImapReadinessOutcome() = runBlocking {
        data class Case(
            val name: String,
            val registry: DovecotAccountRegistry,
            val cachedPassword: String?,
            val outcome: AuthenticationOutcome,
            val expected: CredentialReadiness,
            val expectedProbeCount: Int,
        )
        val cases = listOf(
            Case(
                "active-plain-ready",
                MutablePlainAccountRegistry("active-password"),
                null,
                AuthenticationOutcome.Authenticated("authenticated"),
                CredentialReadiness.READY,
                1,
            ),
            Case(
                "cached-hash-fallback-ready",
                SingleAccount,
                "verified-password",
                AuthenticationOutcome.Authenticated("authenticated"),
                CredentialReadiness.READY,
                1,
            ),
            Case(
                "password-required",
                SingleAccount,
                null,
                AuthenticationOutcome.MissingCredentials("credentials required"),
                CredentialReadiness.PASSWORD_REQUIRED,
                0,
            ),
            Case(
                "wrong-password",
                MutablePlainAccountRegistry("wrong-password"),
                null,
                AuthenticationOutcome.WrongPassword("authentication failed"),
                CredentialReadiness.AUTHENTICATION_FAILED,
                1,
            ),
            Case(
                "missing-account",
                MutablePlainAccountRegistry("password"),
                null,
                AuthenticationOutcome.MissingAccount("unknown user"),
                CredentialReadiness.AUTHENTICATION_FAILED,
                1,
            ),
            Case(
                "unavailable",
                MutablePlainAccountRegistry("password"),
                null,
                AuthenticationOutcome.Unavailable("connection refused"),
                CredentialReadiness.PROVIDER_UNAVAILABLE,
                1,
            ),
            Case(
                "timeout",
                MutablePlainAccountRegistry("password"),
                null,
                AuthenticationOutcome.TimedOut("read timed out"),
                CredentialReadiness.PROVIDER_UNAVAILABLE,
                1,
            ),
        )

        cases.forEach { case ->
            val directory = createTempDirectory("dovecot-readiness-${case.name}").toRealPath()
            try {
                val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
                case.cachedPassword?.let { password ->
                    catalog.put(
                        LocalAccountRecord(
                            provider = Provider.DOVECOT,
                            address = "alice@local.test",
                            password = password,
                            protocols = ALL_PROTOCOLS,
                        ),
                    )
                }
                val mailbox = RecordingMailboxClient(probeOutcome = case.outcome)
                val provider = DovecotDashboardProvider(
                    adapter = DovecotProductAdapter(case.registry, QueueRunner()),
                    catalog = catalog,
                    mailboxClient = mailbox,
                )

                val account = provider.listAccounts().single()

                assertEquals(case.expected, account.credentialReadiness, case.name)
                assertEquals(case.outcome.diagnostic.takeIf { case.expected != CredentialReadiness.PASSWORD_REQUIRED }, account.readinessMessage)
                assertEquals(case.expectedProbeCount, mailbox.probed.size, case.name)
            } finally {
                directory.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun passwordAdoptionPersistsOnlyAfterSuccessfulOrdinaryImapAuthentication() = runBlocking {
        listOf(
            AuthenticationOutcome.Authenticated("authenticated") to CredentialReadiness.READY,
            AuthenticationOutcome.WrongPassword("authentication failed") to
                CredentialReadiness.AUTHENTICATION_FAILED,
            AuthenticationOutcome.Unavailable("connection refused") to
                CredentialReadiness.PROVIDER_UNAVAILABLE,
        ).forEachIndexed { index, (outcome, expectedReadiness) ->
            val directory = createTempDirectory("dovecot-adopt-$index").toRealPath()
            try {
                val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
                val mailbox = RecordingMailboxClient(probeOutcome = outcome)
                val provider = DovecotDashboardProvider(
                    adapter = DovecotProductAdapter(SingleAccount, QueueRunner()),
                    catalog = catalog,
                    mailboxClient = mailbox,
                )

                val response = provider.adoptPassword(
                    "alice@local.test",
                    AdoptPasswordRequest("supplied-password"),
                )

                assertEquals(expectedReadiness, response.readiness)
                assertEquals(outcome is AuthenticationOutcome.Authenticated, response.operation.success)
                assertEquals(1, mailbox.probed.size)
                assertEquals(
                    if (outcome is AuthenticationOutcome.Authenticated) "supplied-password" else null,
                    catalog.find(Provider.DOVECOT, "alice@local.test")?.password,
                )
            } finally {
                directory.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun explicitProbesUseRememberedOverrideAndEmptyCredentialsWithoutPersistingOverrides() =
        runBlocking {
            val directory = createTempDirectory("dovecot-explicit-probes").toRealPath()
            try {
                val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
                catalog.put(
                    LocalAccountRecord(
                        provider = Provider.DOVECOT,
                        address = "alice@local.test",
                        password = "remembered-password",
                        protocols = ALL_PROTOCOLS,
                    ),
                )
                val connector = RecordingExplicitAuthenticationConnector()
                val provider = DovecotDashboardProvider(
                    adapter = DovecotProductAdapter(SingleAccount, QueueRunner()),
                    catalog = catalog,
                    mailboxClient = RecordingMailboxClient(),
                    authenticationProbe = ProviderAuthenticationProbe(connector),
                )

                val results = listOf(
                    AuthenticationProbeRequest(
                        "alice@local.test",
                        Provider.DOVECOT,
                        AuthenticationProtocol.IMAP,
                    ),
                    AuthenticationProbeRequest(
                        "alice@local.test",
                        Provider.DOVECOT,
                        AuthenticationProtocol.POP3,
                        "override-password",
                    ),
                    AuthenticationProbeRequest(
                        "alice@local.test",
                        Provider.DOVECOT,
                        AuthenticationProtocol.SMTP,
                        "",
                    ),
                    AuthenticationProbeRequest(
                        "alice@local.test",
                        Provider.DOVECOT,
                        AuthenticationProtocol.OAUTH_IMAP,
                        "imap-token",
                    ),
                    AuthenticationProbeRequest(
                        "alice@local.test",
                        Provider.DOVECOT,
                        AuthenticationProtocol.OAUTH_SMTP,
                        "smtp-token",
                    ),
                ).map { request ->
                    provider.probeAuthentication(request).also { result ->
                        assertTrue(result.response.success)
                    }
                }

                assertEquals(
                    listOf(
                        listOf("remembered-password"),
                        listOf("override-password"),
                        emptyList(),
                        listOf("imap-token"),
                        listOf("smtp-token"),
                    ),
                    results.map(LocalAuthenticationProbeResult::secretsToRedact),
                )

                assertEquals(
                    listOf(
                        "remembered-password",
                        "override-password",
                        "",
                        "imap-token",
                        "smtp-token",
                    ),
                    connector.attempts.map(ProviderAuthenticationAttempt::secret),
                )
                assertEquals(
                    listOf(
                        ProviderAuthenticationMechanism.PASSWORD,
                        ProviderAuthenticationMechanism.PASSWORD,
                        ProviderAuthenticationMechanism.PASSWORD,
                        ProviderAuthenticationMechanism.OAUTHBEARER,
                        ProviderAuthenticationMechanism.OAUTHBEARER,
                    ),
                    connector.attempts.map(ProviderAuthenticationAttempt::mechanism),
                )
                assertEquals(
                    "remembered-password",
                    catalog.find(Provider.DOVECOT, "alice@local.test")?.password,
                )
            } finally {
                directory.toFile().deleteRecursively()
            }
        }
    @Test
    fun activePlainPasswordBeatsTheStaleCatalogForMailboxWork() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-authority").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    Provider.DOVECOT,
                    "alice@local.test",
                    "stale-catalog-password",
                    ALL_PROTOCOLS,
                ),
            )
            val registry = MutablePlainAccountRegistry("authority-password")
            val runner = QueueRunner()
            val mailbox = RecordingMailboxClient()
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(registry, runner),
                catalog = catalog,
                mailboxClient = mailbox,
            )

            provider.listFolders("alice@local.test")

            assertTrue(mailbox.credentials.isNotEmpty())
            assertTrue(mailbox.credentials.all { it.password == "authority-password" })
            assertTrue(mailbox.credentials.none { it.password == "stale-catalog-password" })
            assertTrue(runner.requests.isEmpty())
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun createRequiresTheExactServerWideCapabilitiesAndBootstrapsFoldersAsTheUser() =
        runBlocking {
            val directory = createTempDirectory("dovecot-dashboard-create-imap").toRealPath()
            try {
                val registry = MutablePlainAccountRegistry()
                val runner = QueueRunner(DovecotCommandResult.success())
                val mailbox = RecordingMailboxClient(folders = mutableListOf(DovecotFolder("INBOX")))
                val provider = DovecotDashboardProvider(
                    adapter = DovecotProductAdapter(registry, runner),
                    catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                    mailboxClient = mailbox,
                )

                assertFailsWith<IllegalArgumentException> {
                    provider.createAccount(
                        CreateAccountRequest(
                            "subset@local.test",
                            "password",
                            Provider.DOVECOT,
                            listOf(MailProtocol.IMAP, MailProtocol.SMTP),
                        ),
                    )
                }
                val account = provider.createAccount(
                    CreateAccountRequest(
                        "alice@local.test",
                        "new-password",
                        Provider.DOVECOT,
                        ALL_PROTOCOLS,
                    ),
                )

                assertEquals(ALL_PROTOCOLS, account.protocols)
                assertEquals(
                    listOf("INBOX.Drafts", "INBOX.Sent", "INBOX.Trash"),
                    mailbox.created.sorted(),
                )
                assertTrue(mailbox.credentials.all {
                    it == AccountCredentials("alice@local.test", "new-password")
                })
                assertTrue(runner.requests.all { "mailbox" !in it.argv })
            } finally {
                directory.toFile().deleteRecursively()
            }
        }

    @Test
    fun passwordChangeMustLogInAsTheUserWithTheChangedPassword() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-password-imap").toRealPath()
        try {
            val registry = MutablePlainAccountRegistry("old-password")
            val runner = QueueRunner(DovecotCommandResult.success())
            val mailbox = RecordingMailboxClient()
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(registry, runner),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            val response = provider.changePassword("alice@local.test", "changed-password")

            assertEquals(
                AccountCredentials("alice@local.test", "changed-password"),
                mailbox.probed.single(),
            )
            assertEquals(CredentialReadiness.READY, response.readiness)
            assertTrue(response.operation.success)
            assertTrue(runner.requests.all { "mailbox" !in it.argv })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun passwordChangeUsesTheLiveCanonicalAddressForCatalogLookup() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-password-canonical").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    provider = Provider.DOVECOT,
                    address = "alice@local.test",
                    password = "old-password",
                    protocols = ALL_PROTOCOLS,
                ),
            )
            val registry = MutablePlainAccountRegistry("old-password")
            val mailbox = RecordingMailboxClient()
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    registry,
                    QueueRunner(DovecotCommandResult.success()),
                ),
                catalog = catalog,
                mailboxClient = mailbox,
            )

            val response = provider.changePassword("ALICE@LOCAL.TEST", "changed-password")

            assertEquals("alice@local.test", response.address)
            assertEquals(
                "changed-password",
                catalog.find(Provider.DOVECOT, "alice@local.test")?.password,
            )
            assertEquals(
                AccountCredentials("alice@local.test", "changed-password"),
                mailbox.probed.single(),
            )
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun passwordChangeDoesNotReportSuccessWhenOrdinaryAuthenticationFails() = runBlocking {
        listOf<AuthenticationOutcome>(
            AuthenticationOutcome.WrongPassword("authentication failed"),
            AuthenticationOutcome.Unavailable("provider unavailable"),
        ).forEachIndexed { index, outcome ->
            val directory = createTempDirectory("dovecot-dashboard-password-failure-$index")
                .toRealPath()
            try {
                val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
                catalog.put(
                    LocalAccountRecord(
                        Provider.DOVECOT,
                        "alice@local.test",
                        "old-password",
                        ALL_PROTOCOLS,
                    ),
                )
                val registry = MutablePlainAccountRegistry("old-password")
                val provider = DovecotDashboardProvider(
                    adapter = DovecotProductAdapter(
                        registry,
                        QueueRunner(DovecotCommandResult.success()),
                    ),
                    catalog = catalog,
                    mailboxClient = RecordingMailboxClient(probeOutcome = outcome),
                )

                val response = provider.changePassword("alice@local.test", "changed-password")

                assertEquals("changed-password", registry.plainPassword("alice@local.test"))
                assertEquals(
                    if (outcome is AuthenticationOutcome.WrongPassword) {
                        CredentialReadiness.AUTHENTICATION_FAILED
                    } else {
                        CredentialReadiness.PROVIDER_UNAVAILABLE
                    },
                    response.readiness,
                )
                assertTrue(!response.operation.success)
                assertEquals(
                    "old-password",
                    catalog.find(Provider.DOVECOT, "alice@local.test")?.password,
                )
            } finally {
                directory.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun liveDovecotCapabilitiesIgnoreAStaleCatalogSubset() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-fixed-capabilities").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    Provider.DOVECOT,
                    "alice@local.test",
                    "password",
                    listOf(MailProtocol.IMAP),
                ),
            )
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MutablePlainAccountRegistry("password"),
                    QueueRunner(),
                ),
                catalog = catalog,
                mailboxClient = RecordingMailboxClient(),
            )

            assertEquals(ALL_PROTOCOLS, provider.listAccounts().single().protocols)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun userFacingMailboxOperationsNeverInvokeDoveadm() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-mailbox-boundary").toRealPath()
        try {
            val runner = QueueRunner()
            val mailbox = RecordingMailboxClient()
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MutablePlainAccountRegistry("authority-password"),
                    runner,
                ),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            provider.listFolders("alice@local.test")
            provider.createFolder("alice@local.test", "Archive")
            provider.deleteFolder("alice@local.test", "INBOX.Archive")
            provider.listMessages("alice@local.test", "INBOX")
            provider.readMessage("alice@local.test", "7", "INBOX")
            provider.mutateMessages(
                "alice@local.test",
                MutateMessagesRequest(
                    account = "alice@local.test",
                    provider = Provider.DOVECOT,
                    messageIds = listOf("7"),
                    mutationStates = mapOf("7" to TEST_MAILBOX_STATE.encode()),
                    action = MessageAction.MARK_READ,
                    sourceFolderId = "INBOX",
                ),
            )

            assertTrue(runner.requests.isEmpty())
            assertTrue(mailbox.credentials.all { it.password == "authority-password" })
            assertEquals(1, mailbox.commands.size)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun logSelectorResolvesTheRegisteredCanonicalAddress() = runBlocking {
        val directory = createTempDirectory("dovecot-dashboard-log-selector").toRealPath()
        try {
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(SingleAccount, QueueRunner()),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
            )

            assertEquals(
                DashboardLogAccount("alice@local.test"),
                provider.dashboardLogAccount("ALICE@LOCAL.TEST"),
            )
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun defaultMailboxAccountLookupUsesTheCanonicalDovecotRegistry() {
        val adapter = DovecotProductAdapter(
            MutablePlainAccountRegistry("password"),
            QueueRunner(),
        )
        val lookup = DovecotAccountExistence(adapter)
        val client = DovecotImapClient(
            storeFactory = DovecotImapStoreFactory {
                error("Authentication classification must not open a mailbox store")
            },
            authenticationProbe = {
                AuthenticationOutcome.WrongPassword("generic authentication failure")
            },
            accountExists = lookup::contains,
        )

        assertTrue(
            client.probe(AccountCredentials("alice@local.test", "wrong-password")) is
                AuthenticationOutcome.WrongPassword,
        )
        assertTrue(
            client.probe(AccountCredentials("missing@local.test", "wrong-password")) is
                AuthenticationOutcome.MissingAccount,
        )
    }

    @Test
    fun messageReadReturnsDecodedPlainAndHtmlMimeBodies() = runBlocking {
        val raw = lines(
            "Subject: Provider reproduction",
            "From: Sender <sender@example.net>",
            "To: alice@local.test",
            "Date: Wed, 05 Aug 2026 12:00:00 +0000",
            "Content-Type: multipart/alternative; boundary=body",
            "",
            "--body",
            "Content-Type: text/plain; charset=UTF-8",
            "Content-Transfer-Encoding: base64",
            "",
            "cmVhZGFibGUgcGxhaW4=",
            "--body",
            "Content-Type: text/html; charset=UTF-8",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<p>readable=20html</p>",
            "--body--",
        )
        val mailbox = RecordingMailboxClient(
            messageSnapshots = listOf(
                listOf(
                    fixtureSummary(
                        uid = 42,
                        messageId = "<message-42@example.net>",
                        subject = "Provider reproduction",
                        flags = setOf("\\Seen"),
                    ),
                ),
            ),
            rawMessage = raw,
        )
        val directory = createTempDirectory("dovecot-dashboard-read").toRealPath()
        try {
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MutablePlainAccountRegistry("password"),
                    QueueRunner(),
                ),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            val detail = provider.readMessage("alice@local.test", "42", "INBOX")

            assertEquals("Provider reproduction", detail.subject)
            assertEquals("readable plain", detail.textBody)
            assertEquals("<p>readable html</p>", detail.htmlBody)
            assertEquals(listOf(TEST_MAILBOX_STATE), mailbox.readStates)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun expectedMessageIdDoesNotFallBackToAnUnrelatedSingletonArrival() = runBlocking {
        val raw = lines(
            "From: sender@local.test",
            "To: alice@local.test",
            "Date: Wed, 05 Aug 2026 12:00:00 +0000",
            "Subject: Correlated fixture",
            "Message-ID: <dashboard-correlated@local.test>",
            "Content-Type: text/plain; charset=UTF-8",
            "",
            "body",
        )
        val runner = QueueRunner(DovecotCommandResult.success())
        val unrelated = fixtureSummary(
            uid = 52,
            messageId = "<unrelated-concurrent@local.test>",
            subject = "Concurrent delivery",
        )
        val correlated = fixtureSummary(
            uid = 51,
            messageId = "<dashboard-correlated@local.test>",
            subject = "Correlated fixture",
        )
        val mailbox = RecordingMailboxClient(
            messageSnapshots = listOf(emptyList(), listOf(unrelated), listOf(correlated, unrelated)),
        )
        val directory = createTempDirectory("dovecot-dashboard-inject").toRealPath()
        try {
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(
                    MutablePlainAccountRegistry("password"),
                    runner,
                ),
                catalog = LocalAccountCatalog(directory.resolve("accounts.json")),
                mailboxClient = mailbox,
            )

            val ids = provider.injectMessages(
                GenerateMessageRequest(
                    targetAccount = "alice@local.test",
                    provider = Provider.DOVECOT,
                    sourceType = MessageSourceType.EML,
                    content = raw,
                ),
                listOf(GeneratedMessage(raw)),
            )

            assertEquals(listOf("51"), ids)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun smtpDeliveryUsesPostfixAndReturnsTheArrivedInboxUid() = runBlocking {
        val raw = lines(
            "From: sender@local.test",
            "To: alice@local.test",
            "Date: Wed, 05 Aug 2026 12:00:00 +0000",
            "Subject: SMTP fixture",
            "Message-ID: <smtp-correlated@local.test>",
            "",
            "body",
        )
        val mailbox = RecordingMailboxClient(
            messageSnapshots = listOf(
                emptyList(),
                listOf(
                    fixtureSummary(
                        uid = 61,
                        messageId = "<smtp-correlated@local.test>",
                        subject = "SMTP fixture",
                    ),
                ),
            ),
        )
        val smtp = RecordingSmtpSender()
        val directory = createTempDirectory("dovecot-dashboard-smtp").toRealPath()
        try {
            val catalog = LocalAccountCatalog(directory.resolve("accounts.json"))
            catalog.put(
                LocalAccountRecord(
                    Provider.DOVECOT,
                    "alice@local.test",
                    "password",
                    listOf(MailProtocol.IMAP, MailProtocol.SMTP),
                ),
            )
            val provider = DovecotDashboardProvider(
                adapter = DovecotProductAdapter(SingleAccount, QueueRunner()),
                catalog = catalog,
                mailboxClient = mailbox,
                smtpSender = smtp,
            )

            val ids = provider.deliverMessages(
                GenerateMessageRequest(
                    targetAccount = "alice@local.test",
                    provider = Provider.DOVECOT,
                    sourceType = MessageSourceType.EML,
                    deliveryMode = MessageDeliveryMode.SMTP_DELIVERY,
                    content = raw,
                ),
                listOf(GeneratedMessage(raw)),
            )

            assertEquals(listOf("61"), ids)
            assertEquals(
                SmtpCall("alice@local.test", "alice@local.test", raw, null),
                smtp.calls.single(),
            )
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private fun lines(vararg values: String): String = values.joinToString("\r\n")

    companion object {
        val ALL_PROTOCOLS = listOf(MailProtocol.IMAP, MailProtocol.POP3, MailProtocol.SMTP)
    }
}

private class RecordingExplicitAuthenticationConnector : ProviderAuthenticationConnector {
    val attempts = mutableListOf<ProviderAuthenticationAttempt>()

    override fun authenticate(
        attempt: ProviderAuthenticationAttempt,
    ): ProviderAuthenticationTransportOutcome {
        attempts += attempt
        return ProviderAuthenticationTransportOutcome.Authenticated("authenticated")
    }
}

private val TEST_MAILBOX_STATE = DovecotMailboxState(uidValidity = 4_242)

private object EmptyAccounts : DovecotAccountRegistry {
    override fun list(): List<String> = emptyList()

    override fun create(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) = verifyProjection()

    override fun changePassword(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) = verifyProjection()

    override fun delete(address: String, verifyProjection: () -> Unit) = verifyProjection()
}

private object SingleAccount : DovecotAccountRegistry by EmptyAccounts {
    override fun list(): List<String> = listOf("alice@local.test")
}

private class MutablePlainAccountRegistry(
    initialPassword: String? = null,
) : DovecotAccountRegistry {
    private val passwords = linkedMapOf<String, String>().apply {
        if (initialPassword != null) put("alice@local.test", initialPassword)
    }

    override fun list(): List<String> = passwords.keys.toList()

    override fun plainPassword(address: String): String? = passwords[address]

    override fun create(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        passwords[address] = password.decodeToString()
        verifyProjection()
    }

    override fun changePassword(
        address: String,
        password: ByteArray,
        verifyProjection: () -> Unit,
    ) {
        passwords[address] = password.decodeToString()
        verifyProjection()
    }

    override fun delete(address: String, verifyProjection: () -> Unit) {
        passwords.remove(address)
        verifyProjection()
    }
}

private class MultipleAccountRegistry(
    private val passwords: LinkedHashMap<String, String?>,
) : DovecotAccountRegistry by EmptyAccounts {
    override fun list(): List<String> = passwords.keys.toList()

    override fun plainPassword(address: String): String? = passwords[address]
}

private class RecordingMailboxClient(
    val folders: MutableList<DovecotFolder> = mutableListOf(DovecotFolder("INBOX")),
    messageSnapshots: List<List<DovecotMessageSummary>> = emptyList(),
    private val rawMessage: String = fixtureRawMessage(),
    private val probeOutcome: AuthenticationOutcome =
        AuthenticationOutcome.Authenticated("authenticated"),
    probeOutcomes: List<AuthenticationOutcome> = emptyList(),
) : DovecotMailboxClient {
    private val messageSnapshots = ArrayDeque(messageSnapshots)
    private val probeOutcomes = ArrayDeque(probeOutcomes)
    private var lastMessageSnapshot: List<DovecotMessageSummary>? = null
    val credentials = mutableListOf<AccountCredentials>()
    val probed = mutableListOf<AccountCredentials>()
    val created = mutableListOf<String>()
    val commands = mutableListOf<DovecotMessageCommand>()
    val readStates = mutableListOf<DovecotMailboxState>()

    override fun probe(credentials: AccountCredentials): AuthenticationOutcome {
        this.credentials += credentials
        probed += credentials
        return probeOutcomes.removeFirstOrNull() ?: probeOutcome
    }

    override fun listFolders(credentials: AccountCredentials): List<DovecotFolder> {
        this.credentials += credentials
        return folders.toList()
    }

    override fun createFolder(
        credentials: AccountCredentials,
        name: String,
    ): DovecotFolder {
        this.credentials += credentials
        created += name
        return DovecotFolder(name).also(folders::add)
    }

    override fun deleteFolder(credentials: AccountCredentials, id: String) {
        this.credentials += credentials
        folders.removeAll { it.name == id }
    }

    override fun listMessages(
        credentials: AccountCredentials,
        folder: String,
    ): List<DovecotMessageSummary> {
        this.credentials += credentials
        val next = messageSnapshots.removeFirstOrNull()
        if (next != null) lastMessageSnapshot = next
        return next ?: lastMessageSnapshot ?: listOf(fixtureSummary())
    }

    override fun readMessage(
        credentials: AccountCredentials,
        folder: String,
        uid: Long,
        expectedState: DovecotMailboxState,
    ): String {
        this.credentials += credentials
        readStates += expectedState
        return rawMessage
    }

    override fun mutate(credentials: AccountCredentials, command: DovecotMessageCommand) {
        this.credentials += credentials
        commands += command
    }
}

private fun fixtureSummary(
    uid: Long = 7,
    messageId: String = "<fixture@local.test>",
    subject: String = "Fixture",
    flags: Set<String> = emptySet(),
): DovecotMessageSummary = DovecotMessageSummary(
    uid = uid,
    mailboxState = TEST_MAILBOX_STATE,
    messageId = messageId,
    subject = subject,
    from = "sender@local.test",
    date = "Tue, 11 Aug 2026 10:00:00 +0000",
    flags = flags,
)

private fun fixtureRawMessage(): String = listOf(
    "From: sender@local.test",
    "To: alice@local.test",
    "Date: Tue, 11 Aug 2026 10:00:00 +0000",
    "Subject: Fixture",
    "Message-ID: <fixture@local.test>",
    "",
    "body",
).joinToString("\r\n")

private data class SmtpCall(
    val envelopeFrom: String,
    val envelopeRecipient: String,
    val rawMessage: String,
    val credentials: LocalSmtpCredentials?,
)

private class RecordingSmtpSender : LocalSmtpSender {
    val calls = mutableListOf<SmtpCall>()

    override fun send(
        envelopeFrom: String,
        envelopeRecipient: String,
        rawMessage: String,
        credentials: LocalSmtpCredentials?,
    ): LocalSmtpSendResult {
        calls += SmtpCall(envelopeFrom, envelopeRecipient, rawMessage, credentials)
        return LocalSmtpSendResult(250, "queued as TEST", "TEST")
    }
}

private class QueueRunner(
    vararg results: DovecotCommandResult,
) : DovecotCommandRunner {
    private val results = ArrayDeque(results.toList())
    val requests = mutableListOf<DovecotCommandRequest>()

    override fun run(request: DovecotCommandRequest): DovecotCommandResult {
        requests += request.copy(stdin = request.stdin.copyOf())
        if ("status" in request.argv) {
            return DovecotCommandResult.success(
                "mailbox: INBOX\n" +
                    "guid: 0123456789abcdef0123456789abcdef\n" +
                    "uidvalidity: 1234\n",
            )
        }
        return results.removeFirstOrNull() ?: error("No Dovecot result configured")
    }
}
