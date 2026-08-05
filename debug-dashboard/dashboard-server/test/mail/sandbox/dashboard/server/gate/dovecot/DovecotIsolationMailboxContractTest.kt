package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.Base64
import javax.net.ssl.SSLContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DovecotIsolationMailboxContractTest {
    @Test
    fun ordinaryAuthenticationReadBudgetCoversPinnedDovecotPenaltyCeiling() {
        assertEquals(1_000, TASK6_PROTOCOL_CONNECT_TIMEOUT_MILLIS)
        assertEquals(
            20_000,
            TASK6_AUTHENTICATION_READ_TIMEOUT_MILLIS,
        )
        assertTrue(
            TASK6_AUTHENTICATION_READ_TIMEOUT_MILLIS >
                DOVECOT_MAX_AUTHENTICATION_PENALTY_MILLIS,
            "The live rejection proof must outlast Dovecot's bounded " +
                "authentication penalty",
        )
    }

    @Test
    fun authenticationDeadlineExpiresAcrossABytewiseDripWithoutResetting() {
        val nowNanos = AtomicLong()
        val appliedTimeouts = mutableListOf<Int>()
        val transcript =
            "+ VXNlcm5hbWU6\r\n".toByteArray(StandardCharsets.US_ASCII)
        val deadline = Task6AuthenticationReadDeadline(
            timeoutMillis = transcript.size,
            nanoTime = nowNanos::get,
            applyReadTimeoutMillis = { timeout ->
                appliedTimeouts.add(timeout)
            },
        )
        val input = object : InputStream() {
            private val delegate = ByteArrayInputStream(transcript)

            override fun read(): Int = delegate.read().also { value ->
                if (value >= 0) {
                    nowNanos.addAndGet(1_000_000L)
                }
            }
        }
        val output = ByteArrayOutputStream()

        assertFailsWith<SocketTimeoutException> {
            task6ProtocolProofForPlainSmtp().ordinaryImapLoginExchange(
                input = input,
                output = output,
                username = "ordinary@local.test"
                    .toByteArray(StandardCharsets.US_ASCII),
                password = "ordinary-secret"
                    .toByteArray(StandardCharsets.US_ASCII),
                readDeadline = deadline,
            )
        }

        assertEquals((transcript.size downTo 1).toList(), appliedTimeouts)
        assertEquals(
            "A601 AUTHENTICATE LOGIN\r\n",
            output.toByteArray().toString(StandardCharsets.US_ASCII),
        )
    }

    @Test
    fun authenticationDeadlineAllowsPinnedPenaltyButExpiresAtExactBoundary() {
        val nowNanos = AtomicLong()
        val appliedTimeouts = mutableListOf<Int>()
        val deadline = Task6AuthenticationReadDeadline(
            timeoutMillis = TASK6_AUTHENTICATION_READ_TIMEOUT_MILLIS,
            nanoTime = nowNanos::get,
            applyReadTimeoutMillis = appliedTimeouts::add,
        )

        nowNanos.set(15_000_000_000L)
        deadline.beforeRead()
        deadline.afterRead()
        nowNanos.set(19_000_000_000L)
        deadline.beforeRead()
        deadline.afterRead()

        assertEquals(listOf(5_000, 1_000), appliedTimeouts)
        nowNanos.set(20_000_000_000L)
        assertFailsWith<SocketTimeoutException> {
            deadline.beforeRead()
        }
        assertFailsWith<SocketTimeoutException> {
            deadline.afterRead()
        }
    }

    @Test
    fun ordinaryImapAcceptsPinned244EarlyPermanentFailureWithoutSendingSecret() {
        val username =
            "target@local.test*dashboard-operator-a"
                .toByteArray(StandardCharsets.US_ASCII)
        val password =
            "ordinary-early-rejection-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val output = ByteArrayOutputStream()
        val input = ByteArrayInputStream(
            (
                "+ VXNlcm5hbWU6\r\n" +
                    "A601 NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )

        try {
            assertEquals(
                DovecotAuthenticationResponse.PermanentFailure,
                task6ProtocolProofForPlainSmtp().ordinaryImapLoginExchange(
                    input = input,
                    output = output,
                    username = username,
                    password = password,
                    readDeadline = task6InMemoryReadDeadline(),
                ),
            )

            val written = output.toByteArray()
            val encodedPassword = Base64.getEncoder().encode(password)
            try {
                assertEquals(
                    "A601 AUTHENTICATE LOGIN\r\n" +
                        Base64.getEncoder().encodeToString(username) +
                        "\r\n",
                    written.toString(StandardCharsets.US_ASCII),
                )
                assertFalse(written.containsSubsequence(encodedPassword))
                assertFalse(written.containsSubsequence(password))
            } finally {
                written.fill(0)
                encodedPassword.fill(0)
            }
        } finally {
            username.fill(0)
            password.fill(0)
            input.close()
            output.close()
        }
    }

    @Test
    fun ordinaryImapRejectsEveryOtherEarlyTerminalAndKeepsNormalLoginPath() {
        val rejectedEarlyLines = listOf(
            "A601 OK authenticated",
            "A601 NO [AUTHORIZATIONFAILED] Authorization failed.",
            "A601 NO [UNAVAILABLE] Authentication unavailable.",
            "A601 BAD malformed",
        )
        rejectedEarlyLines.forEach { terminal ->
            val output = ByteArrayOutputStream()
            assertFailsWith<IllegalStateException>(terminal) {
                task6ProtocolProofForPlainSmtp().ordinaryImapLoginExchange(
                    input = ByteArrayInputStream(
                        (
                            "+ VXNlcm5hbWU6\r\n$terminal\r\n"
                            ).toByteArray(StandardCharsets.US_ASCII),
                    ),
                    output = output,
                    username = "target@local.test*dashboard-operator-a"
                        .toByteArray(StandardCharsets.US_ASCII),
                    password = "must-not-be-written"
                        .toByteArray(StandardCharsets.US_ASCII),
                    readDeadline = task6InMemoryReadDeadline(),
                )
            }
            assertFalse(
                output.toByteArray().toString(StandardCharsets.US_ASCII)
                    .contains(
                        Base64.getEncoder().encodeToString(
                            "must-not-be-written"
                                .toByteArray(StandardCharsets.US_ASCII),
                        ),
                    ),
                terminal,
            )
        }

        val output = ByteArrayOutputStream()
        assertEquals(
            DovecotAuthenticationResponse.PermanentFailure,
            task6ProtocolProofForPlainSmtp().ordinaryImapLoginExchange(
                input = ByteArrayInputStream(
                    (
                        "+ VXNlcm5hbWU6\r\n" +
                            "+ UGFzc3dvcmQ6\r\n" +
                            "A601 NO [AUTHENTICATIONFAILED] " +
                            "Authentication failed.\r\n"
                        ).toByteArray(StandardCharsets.US_ASCII),
                ),
                output = output,
                username = "ordinary@local.test"
                    .toByteArray(StandardCharsets.US_ASCII),
                password = "normal-login-secret"
                    .toByteArray(StandardCharsets.US_ASCII),
                readDeadline = task6InMemoryReadDeadline(),
            ),
        )
        assertTrue(
            output.toByteArray().toString(StandardCharsets.US_ASCII)
                .contains(
                    Base64.getEncoder().encodeToString(
                        "normal-login-secret"
                            .toByteArray(StandardCharsets.US_ASCII),
                    ),
                ),
        )
    }

    @Test
    fun forbiddenOperatorTargetsRequireAnExactAuthorizationFailure() {
        listOf(
            "absent@local.test",
            "dashboard-management@local.test",
            DovecotOperatorId.B.masterUsername,
        ).forEach { target ->
            requireDovecotOperatorTargetRejected(
                target = target,
                activeMasterId = DovecotOperatorId.A,
                response = DovecotOperatorProbeResult.AuthorizationFailure,
            )
        }

        listOf(
            DovecotOperatorProbeResult.Success,
            DovecotOperatorProbeResult.AuthenticationFailure,
            DovecotOperatorProbeResult.ProtocolFailure,
            DovecotOperatorProbeResult.TransportFailure,
        ).forEach { result ->
            assertFailsWith<IllegalStateException>(result.name) {
                requireDovecotOperatorTargetRejected(
                    target = "absent@local.test",
                    activeMasterId = DovecotOperatorId.A,
                    response = result,
                )
            }
        }
    }

    @Test
    fun activeMasterAsTargetRequiresAnExactAuthenticationFailure() {
        DovecotOperatorId.entries.forEach { activeId ->
            requireDovecotOperatorTargetRejected(
                target = activeId.masterUsername,
                activeMasterId = activeId,
                response = DovecotOperatorProbeResult.AuthenticationFailure,
            )
        }

        listOf(
            DovecotOperatorProbeResult.Success,
            DovecotOperatorProbeResult.AuthorizationFailure,
            DovecotOperatorProbeResult.ProtocolFailure,
            DovecotOperatorProbeResult.TransportFailure,
        ).forEach { result ->
            assertFailsWith<IllegalStateException>(result.name) {
                requireDovecotOperatorTargetRejected(
                    target = DovecotOperatorId.A.masterUsername,
                    activeMasterId = DovecotOperatorId.A,
                    response = result,
                )
            }
        }
    }

    @Test
    fun isolationMailboxProofSeedsBeforeStrictReadAndConsumesFreshCredentials() {
        val target = DovecotOperatorTarget.create(
            "task6-isolation-seed@local.test",
        )
        val leases =
            DovecotOperatorApplicationLeaseRegistry(DovecotOperatorId.A)
        val fetchedMessageId =
            "Message-ID: <task6-isolation-read-proof." +
                "${target.address}>\r\n\r\n"
        val seedTransport = Task6ScriptedOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        val readTransport = Task6ScriptedOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "* LIST (\\HasNoChildren) \".\" INBOX\r\n" +
                    "A002 OK list completed\r\n" +
                    "* 1 EXISTS\r\n" +
                    "A003 OK [READ-ONLY] examine completed\r\n" +
                    "* SEARCH 1\r\n" +
                    "A004 OK search completed\r\n" +
                    "* 1 FETCH (UID 1 " +
                    "BODY[HEADER.FIELDS (MESSAGE-ID)] " +
                    "{${fetchedMessageId.length}}\r\n" +
                    fetchedMessageId +
                    ")\r\n" +
                    "A005 OK fetch completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        val openIndex = AtomicInteger()
        val transportFactory = DovecotOperatorTransportFactory { register ->
            when (openIndex.getAndIncrement()) {
                0 -> {
                    assertEquals(
                        1,
                        leases.openLeaseCount(DovecotOperatorId.A),
                    )
                    seedTransport
                }
                1 -> {
                    assertEquals(
                        0,
                        leases.openLeaseCount(DovecotOperatorId.A),
                    )
                    check(seedTransport.closed) {
                        "Seed session must close before the read probe opens"
                    }
                    readTransport
                }
                else -> error("Unexpected Task 6 isolation transport")
            }.also(register)
        }
        val credentials = listOf(
            task6TestCredential("isolation-seed-secret"),
            task6TestCredential("isolation-read-secret"),
        )
        val credentialIndex = AtomicInteger()

        try {
            assertEquals(
                DovecotOperatorProbeResult.Success,
                seedAndProbeTask6IsolationMailbox(
                    leaseRegistry = leases,
                    transportFactory = transportFactory,
                    target = target,
                    credentialSupplier = {
                        credentials[credentialIndex.getAndIncrement()]
                    },
                ),
            )

            val seedWrites = seedTransport.writtenBytes()
                .toString(StandardCharsets.US_ASCII)
            val appendIndex = seedWrites.indexOf(
                "A002 APPEND \"INBOX\" {",
            )
            val messageIdIndex = seedWrites.indexOf(
                "Message-ID: <task6-isolation-read-proof." +
                    "${target.address}>",
            )
            assertTrue(appendIndex >= 0)
            assertTrue(messageIdIndex > appendIndex)
            assertTrue(
                readTransport.writtenBytes()
                    .toString(StandardCharsets.US_ASCII)
                    .contains("A004 UID SEARCH ALL\r\n"),
            )
            assertEquals(2, openIndex.get())
            assertEquals(2, credentialIndex.get())
            assertEquals(
                0,
                leases.openLeaseCount(DovecotOperatorId.A),
            )
            assertTrue(seedTransport.closed)
            assertTrue(readTransport.closed)
            credentials.forEach { credential ->
                assertFailsWith<IllegalStateException> {
                    credential.withSecretBytes { }
                }
            }
        } finally {
            credentials.forEach(DovecotOperatorCredential::close)
            seedTransport.close()
            readTransport.close()
        }
    }

    @Test
    fun ordinaryPasswordEscalationUsesTheActualActiveMasterIdentity() {
        assertEquals(
            "target@local.test*dashboard-operator-a",
            task6MasterLogin(
                "target@local.test",
                DovecotOperatorId.A,
            ),
        )
        assertEquals(
            "target@local.test*dashboard-operator-b",
            task6MasterLogin(
                "target@local.test",
                DovecotOperatorId.B,
            ),
        )
    }

    @Test
    fun inactiveMasterRejectionPairsTheOtherFixedIdentityWithTheActiveCredential() {
        DovecotOperatorId.entries.forEach { activeId ->
            val credential = DovecotOperatorCredential(
                id = activeId,
                secret = DovecotOperatorSecret.takeOwnership(
                    "active-master-$activeId"
                        .toByteArray(StandardCharsets.US_ASCII),
                ),
            )
            var observedLogin: String? = null
            var observedCredential: DovecotOperatorCredential? = null
            try {
                task6RequireInactiveMasterRejected(
                    targetAddress = "target@local.test",
                    activeCredential = credential,
                    requireRejected = { combinedLogin, suppliedCredential ->
                        observedLogin = combinedLogin
                        observedCredential = suppliedCredential
                    },
                )

                val inactiveId = DovecotOperatorId.entries.single {
                    it != activeId
                }
                assertEquals(
                    "target@local.test*${inactiveId.masterUsername}",
                    observedLogin,
                )
                assertSame(credential, observedCredential)
            } finally {
                credential.close()
            }
        }
    }

    @Test
    fun inactiveMasterRejectionCompletesItsPortFreeCheckBeforeReturning() {
        val credential = task6TestCredential("inactive-master-cleanup")
        val events = mutableListOf<String>()
        try {
            task6RequireInactiveMasterRejected(
                targetAddress = "target@local.test",
                activeCredential = credential,
                requireRejected = { combinedLogin, suppliedCredential ->
                    events += "check:$combinedLogin"
                    assertSame(credential, suppliedCredential)
                    events += "cleanup"
                },
            )
            events += "returned"

            assertEquals(
                listOf(
                    "check:target@local.test*dashboard-operator-b",
                    "cleanup",
                    "returned",
                ),
                events,
            )
        } finally {
            credential.close()
        }
    }

    @Test
    fun portFreeOperatorRejectionClosesBeforeReturningAndConsumesCredential() {
        val secretBytes =
            "inactive-master-exchange-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(secretBytes),
        )
        val transport = Task6ScriptedOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A901 NO [AUTHENTICATIONFAILED] rejected\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        val exchange = DovecotOperatorBoundedExchange(
            DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
        )
        val proof = task6ProtocolProofForOperatorExchange(exchange)

        proof.requireOperatorImapRejected(
            combinedUsername =
                "target@local.test*dashboard-operator-b",
            credential = credential,
        )

        assertTrue(transport.closed)
        assertTrue(secretBytes.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    @Test
    fun portFreeOperatorRejectionReportsOnlyTheTypedTransportFailure() {
        val secretBytes =
            "operator-diagnostic-secret"
                .toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(secretBytes),
        )
        val rawTransportDetail = "raw-transport-detail"
        val combinedUsername =
            "diagnostic-target@local.test*dashboard-operator-b"
        val exchange = DovecotOperatorBoundedExchange(
            DovecotOperatorTransportFactory {
                throw IOException(rawTransportDetail)
            },
        )
        val proof = task6ProtocolProofForOperatorExchange(exchange)

        val failure = assertFailsWith<IllegalStateException> {
            proof.requireOperatorImapRejected(
                combinedUsername = combinedUsername,
                credential = credential,
            )
        }

        assertEquals(
            "Operator IMAP rejection was not permanent: TransportFailure",
            failure.message,
        )
        assertFalse(failure.message.orEmpty().contains(combinedUsername))
        assertFalse(failure.message.orEmpty().contains(rawTransportDetail))
        assertFalse(
            failure.message.orEmpty().contains("operator-diagnostic-secret"),
        )
        assertTrue(secretBytes.all { it == 0.toByte() })
    }

    @Test
    fun ordinaryImapProofCannotAcceptAnOperatorPort() {
        val publicHelper =
            DovecotIsolationProtocolProof::class.java.declaredMethods
                .single { method ->
                    method.name == "requireOrdinaryImapRejected"
                }
        val rawHelper =
            DovecotIsolationProtocolProof::class.java.declaredMethods
                .single { method ->
                    method.name == "ordinaryImapLogin"
                }

        assertEquals(
            listOf(
                String::class.java,
                DovecotOperatorCredential::class.java,
            ),
            publicHelper.parameterTypes.toList(),
        )
        assertFalse(
            Int::class.javaPrimitiveType in rawHelper.parameterTypes,
            "Ordinary IMAP must use the endpoint frozen by its proof profile",
        )
    }

    @Test
    fun disposableEligibilityFixtureCleansUpAnAddThatMutatesBeforeFailure() {
        val address = "task6-fixture@local.test"
        val events = mutableListOf<String>()
        var eligible = false
        val passwordBytes =
            "task6-fixture-password".toByteArray(StandardCharsets.US_ASCII)
        lateinit var fixture: Task6DisposableEligibilityFixture
        val gateway = object : Task6DisposableEligibilityGateway {
            override fun contains(candidate: String): Boolean {
                assertEquals(address, candidate)
                events += "contains:$eligible"
                return eligible
            }

            override fun add(
                candidate: String,
                password: EligibilityPassword,
            ): Int {
                assertEquals(address, candidate)
                assertTrue(fixture.addAttempted)
                password.withBytes { supplied ->
                    assertTrue(supplied.contentEquals(passwordBytes))
                }
                events += "add"
                eligible = true
                return 2
            }

            override fun remove(candidate: String): Int {
                assertEquals(address, candidate)
                events += "remove"
                eligible = false
                return 0
            }
        }
        fixture = Task6DisposableEligibilityFixture(
            address = address,
            passwordFactory = {
                EligibilityPassword.takeOwnership(passwordBytes)
            },
            gateway = gateway,
            rejectionProof = {
                events += "rejection"
                assertFalse(eligible)
            },
        )

        assertFailsWith<IllegalStateException> {
            fixture.run {
                events += "body"
            }
        }

        assertTrue(fixture.addAttempted)
        assertFalse(eligible)
        assertEquals(
            listOf(
                "contains:false",
                "add",
                "contains:true",
                "remove",
                "rejection",
            ),
            events,
        )
        assertTrue(passwordBytes.all { it == 0.toByte() })
    }

    @Test
    fun smtpRejectionRequiresAnExactTerminal535Reply() {
        val proof = task6ProtocolProofForPlainSmtp()
        listOf(
            "5350 malformed",
            "535-continuation",
            "535 \u0000",
            "535 \u007f",
        ).forEachIndexed { index, terminalReply ->
            val credential = task6TestCredential("smtp-malformed-$index")
            try {
                withTask6SmtpServer(terminalReply) { port ->
                    assertFailsWith<IllegalStateException> {
                        proof.requireSmtpRejected(
                            port = port,
                            username =
                                "target@local.test*dashboard-operator-a",
                            credential = credential,
                        )
                    }
                }
            } finally {
                credential.close()
            }
        }

        val acceptedCredential = task6TestCredential("smtp-terminal")
        try {
            withTask6SmtpServer("535 Authentication rejected") { port ->
                proof.requireSmtpRejected(
                    port = port,
                    username =
                        "target@local.test*dashboard-operator-a",
                    credential = acceptedCredential,
                )
            }
        } finally {
            acceptedCredential.close()
        }
    }

    @Test
    fun smtpAcceptsEarlyTerminal535AfterUsernameWithoutSendingSecret() {
        val proof = task6ProtocolProofForPlainSmtp()
        val credential = task6TestCredential("smtp-early-terminal-secret")
        try {
            withTask6SmtpServer(
                terminalReply = "535 Authentication rejected",
                rejectAfterUsername = true,
            ) { port ->
                proof.requireSmtpRejected(
                    port = port,
                    username =
                        "target@local.test*dashboard-operator-a",
                    credential = credential,
                )
            }
        } finally {
            credential.close()
        }
    }

    @Test
    fun smtpEarlyUsernameResponseRejectsSuccessTemporaryAndMalformedReplies() {
        val proof = task6ProtocolProofForPlainSmtp()
        listOf(
            "235 authenticated",
            "454 temporary failure",
            "5350 malformed",
            "535-continuation",
            "535 \u0000",
            "535 \u007f",
        ).forEachIndexed { index, earlyReply ->
            val credential = task6TestCredential("smtp-early-malformed-$index")
            try {
                withTask6SmtpServer(
                    terminalReply = earlyReply,
                    rejectAfterUsername = true,
                ) { port ->
                    assertFailsWith<IllegalStateException>(earlyReply) {
                        proof.requireSmtpRejected(
                            port = port,
                            username =
                                "target@local.test*dashboard-operator-a",
                            credential = credential,
                        )
                    }
                }
            } finally {
                credential.close()
            }
        }
    }

    private fun task6ProtocolProofForPlainSmtp():
        DovecotIsolationProtocolProof {
        val constructor =
            DovecotIsolationProtocolProof::class.java.getDeclaredConstructor(
                SSLContext::class.java,
            )
        constructor.isAccessible = true
        return constructor.newInstance(SSLContext.getDefault())
    }

    private fun task6InMemoryReadDeadline(): Task6ProtocolReadDeadline =
        object : Task6ProtocolReadDeadline {
            override fun beforeRead() = Unit

            override fun afterRead() = Unit
        }

    private fun task6ProtocolProofForOperatorExchange(
        exchange: DovecotOperatorBoundedExchange,
    ): DovecotIsolationProtocolProof {
        val constructor =
            DovecotIsolationProtocolProof::class.java.getDeclaredConstructor(
                SSLContext::class.java,
                DovecotOperatorBoundedExchange::class.java,
            )
        constructor.isAccessible = true
        return constructor.newInstance(SSLContext.getDefault(), exchange)
    }

    private fun withTask6SmtpServer(
        terminalReply: String,
        rejectAfterUsername: Boolean = false,
        block: (Int) -> Unit,
    ) {
        val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val server = ServerSocket(0, 1, loopback)
        val serverFailure = AtomicReference<Throwable?>()
        val completed = CountDownLatch(1)
        val worker = Thread(
            {
                try {
                    server.accept().use { socket ->
                        val reader = BufferedReader(
                            InputStreamReader(
                                socket.inputStream,
                                StandardCharsets.US_ASCII,
                            ),
                        )
                        fun send(line: String) {
                            val bytes =
                                "$line\r\n".toByteArray(
                                    StandardCharsets.US_ASCII,
                                )
                            try {
                                socket.outputStream.write(bytes)
                                socket.outputStream.flush()
                            } finally {
                                bytes.fill(0)
                            }
                        }

                        send("220 task6-proof ready")
                        checkNotNull(reader.readLine())
                        send("250 task6-proof ready")
                        checkNotNull(reader.readLine())
                        send("334 VXNlcm5hbWU6")
                        checkNotNull(reader.readLine())
                        if (rejectAfterUsername) {
                            send(terminalReply)
                            socket.soTimeout = 1_000
                            assertEquals(
                                null,
                                reader.readLine(),
                                "SMTP proof sent a password after an early " +
                                    "terminal rejection",
                            )
                        } else {
                            send("334 UGFzc3dvcmQ6")
                            checkNotNull(reader.readLine())
                            send(terminalReply)
                        }
                    }
                } catch (failure: Throwable) {
                    serverFailure.set(failure)
                } finally {
                    completed.countDown()
                }
            },
            "task6-smtp-contract-server",
        ).also {
            it.isDaemon = true
            it.start()
        }

        try {
            block(server.localPort)
        } finally {
            runCatching(server::close)
            assertTrue(
                completed.await(2, TimeUnit.SECONDS),
                "SMTP contract server did not finish",
            )
            serverFailure.get()?.let { throw it }
            worker.join(2_000)
        }
    }

    private fun task6TestCredential(
        secret: String,
    ): DovecotOperatorCredential =
        DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                secret.toByteArray(StandardCharsets.US_ASCII),
            ),
        )

    private companion object {
        const val DOVECOT_MAX_AUTHENTICATION_PENALTY_MILLIS = 15_000
    }
}

private fun ByteArray.containsSubsequence(candidate: ByteArray): Boolean {
    if (candidate.isEmpty() || candidate.size > size) return false
    return (0..size - candidate.size).any { offset ->
        candidate.indices.all { index -> this[offset + index] == candidate[index] }
    }
}

private class Task6ScriptedOperatorTransport(
    transcript: ByteArray,
) : DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(transcript)
    private val outputBytes = ByteArrayOutputStream()

    var closed = false
        private set

    override val input: InputStream = inputBytes
    override val outputStream: OutputStream = outputBytes

    fun writtenBytes(): ByteArray = outputBytes.toByteArray()

    override fun abort() {
        close()
    }

    override fun close() {
        if (closed) return
        closed = true
        inputBytes.close()
        outputBytes.close()
    }
}
