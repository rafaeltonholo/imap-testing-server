package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DovecotOperatorRotationLiveTest {
    @Test
    fun stageProbeSwitchRevokeUsesTheNewApplicationLeaseAndDrainsOldSessions() {
        val repositoryRoot = repositoryRoot()
        val live = DovecotLiveTestEnvironment.load(
            environment = System.getenv(),
            repositoryRoot = repositoryRoot,
        )
        live.awaitReady()
        val address =
            "task6-rotation-" +
                UUID.randomUUID().toString().replace("-", "") +
                "@local.test"
        val target = DovecotOperatorTarget.create(address)
        val eligibilityPaths = live.profile.eligibilityPaths()
        val eligibilityCli = EligibilityFileCli(
            pathsProvider = { eligibilityPaths },
            hasherFactory = { root ->
                DovecotPasswordHasher(
                    root,
                    JvmEligibilityProcessRunner(
                        dockerRouting =
                            DovecotDockerRouting.task5Proof(live.profile),
                    ),
                )
            },
        )
        val operatorPaths = live.profile.operatorPaths()
        val store = DovecotOperatorCredentialStore(
            paths = operatorPaths,
            generator = SecureDovecotOperatorSecretGenerator(),
            hasher = ExistingDovecotOperatorHashBoundary(
                DovecotPasswordHasher(
                    repositoryRoot,
                    JvmEligibilityProcessRunner(
                        dockerRouting =
                            DovecotDockerRouting.task5Proof(live.profile),
                    ),
                ),
            ),
            verifier = ExistingDovecotOperatorHashVerifier(
                repositoryRoot,
                JvmEligibilityProcessRunner(
                    dockerRouting =
                        DovecotDockerRouting.task5Proof(live.profile),
                ),
            ),
        )
        val transportFactory =
            JvmJsseDovecotOperatorTransportFactory.task5Proof(
                live.profile,
            )
        val probe = DovecotOperatorProbe(
            transportFactory = transportFactory,
            requireMailboxRead = true,
        )
        val oldId = store.loadActive().use { it.id }
        val leases = DovecotOperatorApplicationLeaseRegistry(oldId)
        val runtime = DovecotOperatorLeasedRotationRuntime(
            leases = leases,
            prober = probe::probe,
        )
        var oldLease: DovecotOperatorApplicationLease? = null
        var heldOldSession: HeldDovecotOperatorImapSession? = null
        var targetAdded = false
        var primaryFailure: Throwable? = null
        try {
            require(address !in EligibilityFile(eligibilityPaths).list()) {
                "Disposable rotation target unexpectedly exists"
            }
            generateTargetPassword().use { password ->
                addEligibleTarget(eligibilityCli, address, password)
            }
            targetAdded = true

            val oldCredential = store.loadActive()
            val seedMessage = deterministicRotationMessage(target)
            val oldSession = try {
                check(oldCredential.id == oldId) {
                    "Dovecot operator active ID changed before session hold"
                }
                HeldDovecotOperatorImapSession.openAndSeed(
                    transportFactory = transportFactory,
                    target = target,
                    credential = oldCredential,
                    message = seedMessage,
                )
            } catch (failure: Throwable) {
                oldCredential.close()
                seedMessage.fill(0)
                throw failure
            }
            heldOldSession = oldSession
            val lease = try {
                leases.acquire(oldId, oldSession::close)
            } catch (failure: Throwable) {
                oldSession.close()
                throw failure
            }
            oldLease = lease
            oldSession.requireUsable()

            val newId = store.rotateOrRecover(target, runtime)

            assertNotEquals(oldId, newId)
            assertFalse(lease.isOpen)
            assertTrue(oldSession.isClosed)
            oldSession.requireClosedAndUnusable()
            assertEquals(0, leases.openLeaseCount(oldId))
            assertEquals(newId, store.loadActive().use { it.id })
            assertEquals(
                DovecotOperatorProbeResult.Success,
                probe.probe(target, store.loadActive()),
            )
            assertFalse(
                Files.exists(
                    operatorPaths.slot(oldId),
                    java.nio.file.LinkOption.NOFOLLOW_LINKS,
                ),
            )
            assertFalse(
                Files.exists(
                    operatorPaths.rotationIntent,
                    java.nio.file.LinkOption.NOFOLLOW_LINKS,
                ),
            )
            assertTrue(
                Files.exists(
                    operatorPaths.slot(newId),
                    java.nio.file.LinkOption.NOFOLLOW_LINKS,
                ),
            )
            val masterLines = Files.readAllLines(
                operatorPaths.masterUsers,
                StandardCharsets.US_ASCII,
            )
            assertEquals(1, masterLines.size)
            assertTrue(
                masterLines.single().startsWith(
                    "${newId.masterUsername}:",
                ),
            )
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            var cleanupFailure: Throwable? = null
            fun attemptCleanup(block: () -> Unit) {
                try {
                    block()
                } catch (failure: Throwable) {
                    val existing = cleanupFailure
                    if (existing == null) {
                        cleanupFailure = failure
                    } else if (existing !== failure) {
                        existing.addSuppressed(failure)
                    }
                }
            }
            attemptCleanup {
                if (
                    Files.exists(
                        operatorPaths.rotationIntent,
                        java.nio.file.LinkOption.NOFOLLOW_LINKS,
                    )
                ) {
                    store.recoverRotation(target, runtime)
                }
            }
            attemptCleanup {
                runtime.close()
            }
            attemptCleanup {
                oldLease?.close()
            }
            attemptCleanup {
                heldOldSession?.close()
            }
            attemptCleanup {
                if (
                    targetAdded &&
                    address in EligibilityFile(eligibilityPaths).list()
                ) {
                    removeEligibleTarget(eligibilityCli, address)
                }
            }
            if (targetAdded) {
                attemptCleanup {
                    awaitDovecotOperatorTargetRejection(
                        resultSupplier = {
                            probe.probe(target, store.loadActive())
                        },
                    )
                }
            }
            cleanupFailure?.let { failure ->
                val primary = primaryFailure
                if (primary != null) {
                    primary.addSuppressed(failure)
                } else {
                    throw failure
                }
            }
        }
    }

    private fun generateTargetPassword(): EligibilityPassword {
        val bytes = ByteArray(TARGET_PASSWORD_BYTES)
        try {
            bytes.indices.forEach { index ->
                bytes[index] = TARGET_PASSWORD_ALPHABET[
                    SECURE_RANDOM.nextInt(TARGET_PASSWORD_ALPHABET.length)
                ].code.toByte()
            }
            return EligibilityPassword.takeOwnership(bytes)
        } catch (failure: Throwable) {
            bytes.fill(0)
            throw failure
        }
    }

    private fun addEligibleTarget(
        cli: EligibilityFileCli,
        address: String,
        password: EligibilityPassword,
    ) {
        var input = ByteArray(0)
        try {
            password.withBytes { bytes ->
                input = ByteArray(bytes.size + 1)
                bytes.copyInto(input)
                input[input.lastIndex] = '\n'.code.toByte()
            }
            assertEquals(
                0,
                executeEligibility(
                    cli,
                    arrayOf("add", address),
                    input,
                ),
                "Disposable rotation target add failed",
            )
        } finally {
            input.fill(0)
        }
    }

    private fun removeEligibleTarget(
        cli: EligibilityFileCli,
        address: String,
    ) {
        assertEquals(
            0,
            executeEligibility(
                cli,
                arrayOf("remove", address),
                ByteArray(0),
            ),
            "Disposable rotation target cleanup failed",
        )
    }

    private fun executeEligibility(
        cli: EligibilityFileCli,
        args: Array<String>,
        stdin: ByteArray,
    ): Int {
        val sink = PrintStream(
            OutputStream.nullOutputStream(),
            true,
            StandardCharsets.UTF_8,
        )
        return sink.use { output ->
            cli.execute(
                args = args,
                stdin = ByteArrayInputStream(stdin),
                stdout = output,
                stderr = output,
            )
        }
    }

    private fun repositoryRoot(): Path {
        val working = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot =
            if (working.fileName?.toString() == "dashboard-server") {
                requireNotNull(working.parent)
            } else {
                working
            }
        return requireNotNull(dashboardRoot.parent).also { root ->
            require(Files.isRegularFile(root.resolve("docker-compose.yml")))
        }
    }

    companion object {
        private const val TARGET_PASSWORD_BYTES = 48
        private const val TARGET_PASSWORD_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        private val SECURE_RANDOM = SecureRandom()
    }
}

private fun deterministicRotationMessage(
    target: DovecotOperatorTarget,
): ByteArray =
    (
        "From: dashboard-rotation@local.test\r\n" +
            "To: ${target.address}\r\n" +
            "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
            "Subject: Dovecot Task 6 rotation proof\r\n" +
            "Message-ID: <task6-rotation-read-proof.${target.address}>\r\n" +
            "MIME-Version: 1.0\r\n" +
            "Content-Type: text/plain; charset=UTF-8\r\n" +
            "\r\n" +
            "Deterministic Dovecot Task 6 mailbox read proof.\r\n"
        ).toByteArray(StandardCharsets.US_ASCII)

class DovecotHeldOperatorImapSessionTest {
    @Test
    fun rotationSeedMessageIdIsStableAndUniqueForEachDisposableTarget() {
        val firstTarget = DovecotOperatorTarget.create(
            "task6-rotation-first@local.test",
        )
        val secondTarget = DovecotOperatorTarget.create(
            "task6-rotation-second@local.test",
        )
        val firstMessage = deterministicRotationMessage(firstTarget)
        val repeatedFirstMessage = deterministicRotationMessage(firstTarget)
        val secondMessage = deterministicRotationMessage(secondTarget)

        try {
            assertContentEquals(firstMessage, repeatedFirstMessage)
            assertEquals(
                "<task6-rotation-read-proof." +
                    "task6-rotation-first@local.test>",
                messageId(firstMessage),
            )
            assertNotEquals(
                messageId(firstMessage),
                messageId(secondMessage),
            )
        } finally {
            firstMessage.fill(0)
            repeatedFirstMessage.fill(0)
            secondMessage.fill(0)
        }
    }

    @Test
    fun seedsTheMailboxProvesTheLiveSessionThenClosesItsTransport() {
        val message = (
            "From: sender@local.test\r\n" +
                "To: task6-held-session@local.test\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 rotation proof\r\n" +
                "Message-ID: <task6-held-session@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Deterministic Dovecot Task 6 mailbox read proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        val expectedMessage = message.copyOf()
        val target = DovecotOperatorTarget.create(
            "task6-held-session@local.test",
        )
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "held-session-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        val transport = ScriptedHeldOperatorTransport(
            (
                "* OK Dovecot ready\r\n" +
                    "+ VXNlcm5hbWU6\r\n" +
                    "+ UGFzc3dvcmQ6\r\n" +
                    "A001 OK authenticated\r\n" +
                    "+ OK continue\r\n" +
                    "A002 OK append completed\r\n" +
                    "A003 OK noop completed\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )

        val session = HeldDovecotOperatorImapSession.openAndSeed(
            transportFactory = DovecotOperatorTransportFactory { register ->
                register(transport)
                transport
            },
            target = target,
            credential = credential,
            message = message,
        )
        session.requireUsable()

        assertContentEquals(
            heldSessionExpectedWrites(
                target = target,
                credentialId = DovecotOperatorId.A,
                secret = "held-session-secret",
                message = expectedMessage,
            ),
            transport.writtenBytes(),
        )
        assertTrue(message.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
        assertFalse(session.isClosed)
        assertFalse(transport.closed)

        session.close()

        assertTrue(session.isClosed)
        assertTrue(transport.closed)
        session.requireClosedAndUnusable()
    }

    @Test
    fun invalidSeedStillWipesTheMessageAndClosesTheCredential() {
        val invalidMessage =
            "not-an-rfc5322-message".toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "invalid-seed-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = DovecotOperatorTransportFactory {
                    error("Invalid input must fail before opening transport")
                },
                target = DovecotOperatorTarget.create(
                    "task6-invalid-seed@local.test",
                ),
                credential = credential,
                message = invalidMessage,
            )
        }

        assertTrue(invalidMessage.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    @Test
    fun rejectedUnregisteredTransportIsClosed() {
        val message = (
            "From: sender@local.test\r\n" +
                "To: task6-unregistered@local.test\r\n" +
                "Date: Thu, 30 Jul 2026 12:00:00 +0000\r\n" +
                "Subject: Dovecot Task 6 allocation proof\r\n" +
                "Message-ID: <task6-unregistered@local.test>\r\n" +
                "MIME-Version: 1.0\r\n" +
                "Content-Type: text/plain; charset=UTF-8\r\n" +
                "\r\n" +
                "Allocation proof.\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)
        val credential = DovecotOperatorCredential(
            id = DovecotOperatorId.A,
            secret = DovecotOperatorSecret.takeOwnership(
                "unregistered-secret".toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        val transport = ScriptedHeldOperatorTransport(ByteArray(0))

        assertFailsWith<IllegalStateException> {
            HeldDovecotOperatorImapSession.openAndSeed(
                transportFactory = DovecotOperatorTransportFactory {
                    transport
                },
                target = DovecotOperatorTarget.create(
                    "task6-unregistered@local.test",
                ),
                credential = credential,
                message = message,
            )
        }

        assertTrue(transport.closed)
        assertTrue(message.all { it == 0.toByte() })
        assertFailsWith<IllegalStateException> {
            credential.withSecretBytes { }
        }
    }

    private fun heldSessionExpectedWrites(
        target: DovecotOperatorTarget,
        credentialId: DovecotOperatorId,
        secret: String,
        message: ByteArray,
    ): ByteArray = ByteArrayOutputStream().use { expected ->
        expected.write("A001 AUTHENTICATE LOGIN\r\n".toByteArray())
        expected.write(
            Base64.getEncoder().encode(
                (
                    target.address +
                        "*" +
                        credentialId.masterUsername
                    ).toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        expected.write("\r\n".toByteArray())
        expected.write(
            Base64.getEncoder().encode(
                secret.toByteArray(StandardCharsets.US_ASCII),
            ),
        )
        expected.write("\r\n".toByteArray())
        expected.write(
            (
                "A002 APPEND \"INBOX\" {${message.size}}\r\n"
                ).toByteArray(StandardCharsets.US_ASCII),
        )
        expected.write(message)
        expected.write("\r\n".toByteArray())
        expected.write("A003 NOOP\r\n".toByteArray())
        expected.toByteArray()
    }

    private fun messageId(message: ByteArray): String =
        message.toString(StandardCharsets.US_ASCII)
            .lineSequence()
            .single { line -> line.startsWith("Message-ID: ") }
            .removePrefix("Message-ID: ")
}

private class ScriptedHeldOperatorTransport(
    transcript: ByteArray,
) : DovecotOperatorTransport {
    private val inputBytes = ByteArrayInputStream(transcript)
    private val outputBytes = ByteArrayOutputStream()
    var closed = false
        private set

    override val input = inputBytes
    override val outputStream: OutputStream = object : OutputStream() {
        override fun write(value: Int) {
            check(!closed) { "Held transport is closed" }
            outputBytes.write(value)
        }

        override fun write(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ) {
            check(!closed) { "Held transport is closed" }
            outputBytes.write(bytes, offset, length)
        }
    }

    fun writtenBytes(): ByteArray = outputBytes.toByteArray()

    override fun abort() {
        close()
    }

    override fun close() {
        closed = true
        inputBytes.close()
        outputBytes.close()
    }
}

private class HeldDovecotOperatorImapSession private constructor(
    private val transport: DovecotOperatorTransport,
) : AutoCloseable {
    @Volatile
    private var closed = false

    val isClosed: Boolean
        get() = closed

    @Synchronized
    fun requireUsable() {
        check(!closed) { "Held Dovecot operator session is closed" }
        val deadline = System.nanoTime() + SESSION_DEADLINE_NANOS
        writeFixed(
            transport,
            USABILITY_NOOP_COMMAND,
            deadline,
        )
        requireTaggedOkay(
            transport,
            USABILITY_NOOP_TAG,
            deadline,
        )
    }

    fun requireClosedAndUnusable() {
        check(closed) { "Held Dovecot operator session remains open" }
        val command = CLOSED_SESSION_NOOP_COMMAND.copyOf()
        try {
            val rejected = try {
                transport.outputStream.write(command)
                transport.outputStream.flush()
                false
            } catch (_: Exception) {
                true
            }
            check(rejected) {
                "Closed Dovecot operator transport remained usable"
            }
        } finally {
            command.fill(0)
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        transport.close()
        closed = true
    }

    companion object {
        fun openAndSeed(
            transportFactory: DovecotOperatorTransportFactory,
            target: DovecotOperatorTarget,
            credential: DovecotOperatorCredential,
            message: ByteArray,
        ): HeldDovecotOperatorImapSession {
            var allocated: DovecotOperatorTransport? = null
            var returned: DovecotOperatorTransport? = null
            val deadline = System.nanoTime() + SESSION_DEADLINE_NANOS
            return try {
                requireValidMessage(message)
                val opened = transportFactory.open { candidate ->
                    check(allocated == null) {
                        "Held Dovecot operator transport allocation is invalid"
                    }
                    allocated = candidate
                }
                returned = opened
                check(allocated === opened) {
                    "Held Dovecot operator transport allocation is invalid"
                }
                requireGreeting(opened, deadline)
                authenticate(
                    transport = opened,
                    target = target,
                    credential = credential,
                    deadline = deadline,
                )
                appendMessage(opened, message, deadline)
                HeldDovecotOperatorImapSession(opened)
            } catch (failure: Throwable) {
                returned?.let(::abortAndClose)
                allocated
                    ?.takeUnless { it === returned }
                    ?.let(::abortAndClose)
                throw failure
            } finally {
                credential.close()
                message.fill(0)
            }
        }

        private fun requireGreeting(
            transport: DovecotOperatorTransport,
            deadline: Long,
        ) {
            readLine(transport, deadline).useWiped { line ->
                check(line.hasAsciiTokenAt(0, "* OK")) {
                    "Held Dovecot operator greeting was invalid"
                }
            }
        }

        private fun authenticate(
            transport: DovecotOperatorTransport,
            target: DovecotOperatorTarget,
            credential: DovecotOperatorCredential,
            deadline: Long,
        ) {
            writeFixed(
                transport,
                AUTHENTICATE_LOGIN_COMMAND,
                deadline,
            )
            requireExactLine(
                transport,
                USERNAME_CHALLENGE,
                deadline,
            )
            writeCombinedUsername(
                transport,
                target,
                credential.id,
                deadline,
            )
            requireExactLine(
                transport,
                PASSWORD_CHALLENGE,
                deadline,
            )
            credential.withSecretBytes { secret ->
                writeBase64(transport, secret, deadline)
            }
            requireTaggedOkay(transport, "A001", deadline)
        }

        private fun appendMessage(
            transport: DovecotOperatorTransport,
            message: ByteArray,
            deadline: Long,
        ) {
            val appendCommand = (
                "A002 APPEND \"INBOX\" {${message.size}}\r\n"
                ).toByteArray(StandardCharsets.US_ASCII)
            try {
                write(transport, appendCommand, deadline)
            } finally {
                appendCommand.fill(0)
            }
            readLine(transport, deadline).useWiped { continuation ->
                check(
                    continuation.isNotEmpty() &&
                        continuation[0] == '+'.code.toByte(),
                ) {
                    "Held Dovecot operator APPEND continuation was invalid"
                }
            }
            requireBeforeDeadline(deadline)
            transport.outputStream.write(message)
            transport.outputStream.write(CRLF)
            transport.outputStream.flush()
            requireBeforeDeadline(deadline)
            requireTaggedOkay(transport, "A002", deadline)
        }

        private fun writeCombinedUsername(
            transport: DovecotOperatorTransport,
            target: DovecotOperatorTarget,
            id: DovecotOperatorId,
            deadline: Long,
        ) {
            val targetBytes = target.address.toByteArray(
                StandardCharsets.US_ASCII,
            )
            val masterBytes = id.masterUsername.toByteArray(
                StandardCharsets.US_ASCII,
            )
            val combined = ByteArray(
                targetBytes.size + 1 + masterBytes.size,
            )
            try {
                targetBytes.copyInto(combined)
                combined[targetBytes.size] = '*'.code.toByte()
                masterBytes.copyInto(
                    combined,
                    destinationOffset = targetBytes.size + 1,
                )
                writeBase64(transport, combined, deadline)
            } finally {
                targetBytes.fill(0)
                masterBytes.fill(0)
                combined.fill(0)
            }
        }

        private fun writeBase64(
            transport: DovecotOperatorTransport,
            raw: ByteArray,
            deadline: Long,
        ) {
            val encoded = Base64.getEncoder().encode(raw)
            val line = ByteArray(encoded.size + CRLF.size)
            try {
                check(encoded.size <= MAX_AUTH_RESPONSE_BYTES) {
                    "Held Dovecot operator authentication exceeded its bound"
                }
                encoded.copyInto(line)
                CRLF.copyInto(line, destinationOffset = encoded.size)
                write(transport, line, deadline)
            } finally {
                encoded.fill(0)
                line.fill(0)
            }
        }

        private fun writeFixed(
            transport: DovecotOperatorTransport,
            command: ByteArray,
            deadline: Long,
        ) {
            val copy = command.copyOf()
            try {
                write(transport, copy, deadline)
            } finally {
                copy.fill(0)
            }
        }

        private fun write(
            transport: DovecotOperatorTransport,
            bytes: ByteArray,
            deadline: Long,
        ) {
            requireBeforeDeadline(deadline)
            transport.outputStream.write(bytes)
            transport.outputStream.flush()
            requireBeforeDeadline(deadline)
        }

        private fun requireExactLine(
            transport: DovecotOperatorTransport,
            expected: ByteArray,
            deadline: Long,
        ) {
            readLine(transport, deadline).useWiped { line ->
                check(line.contentEquals(expected)) {
                    "Held Dovecot operator continuation was invalid"
                }
            }
        }

        private fun requireTaggedOkay(
            transport: DovecotOperatorTransport,
            tag: String,
            deadline: Long,
        ) {
            repeat(MAX_RESPONSE_LINES) {
                readLine(transport, deadline).useWiped { line ->
                    if (line.hasAsciiTokenAt(0, tag)) {
                        check(line.hasAsciiTokenAt(tag.length + 1, "OK")) {
                            "Held Dovecot operator command failed"
                        }
                        return
                    }
                }
            }
            error("Held Dovecot operator response exceeded its bound")
        }

        private fun readLine(
            transport: DovecotOperatorTransport,
            deadline: Long,
        ): ByteArray {
            val buffer = ByteArray(MAX_LINE_BYTES + 1)
            var size = 0
            try {
                while (true) {
                    requireBeforeDeadline(deadline)
                    val value = transport.input.read()
                    requireBeforeDeadline(deadline)
                    if (value < 0) {
                        throw IOException(
                            "Held Dovecot operator response was truncated",
                        )
                    }
                    if (value == '\n'.code) {
                        check(
                            size > 0 &&
                                buffer[size - 1] == '\r'.code.toByte(),
                        ) {
                            "Held Dovecot operator response was invalid"
                        }
                        return buffer.copyOf(size - 1)
                    }
                    check(size < buffer.size) {
                        "Held Dovecot operator response exceeded its bound"
                    }
                    buffer[size] = value.toByte()
                    size += 1
                }
            } finally {
                buffer.fill(0)
            }
        }

        private fun requireBeforeDeadline(deadline: Long) {
            check(System.nanoTime() - deadline < 0) {
                "Held Dovecot operator session exceeded its deadline"
            }
        }

        private fun requireValidMessage(message: ByteArray) {
            require(message.size in 1..MAX_MESSAGE_BYTES) {
                "Held Dovecot seed message size is invalid"
            }
            require(
                message.all { byte ->
                    byte == '\r'.code.toByte() ||
                        byte == '\n'.code.toByte() ||
                        byte == '\t'.code.toByte() ||
                        byte.toInt() in 0x20..0x7e
                },
            ) {
                "Held Dovecot seed message encoding is invalid"
            }
            val text = message.toString(StandardCharsets.US_ASCII)
            require(
                REQUIRED_MESSAGE_HEADERS.all { header ->
                    text.startsWith("$header:") ||
                        text.contains("\r\n$header:")
                } &&
                    "\r\n\r\n" in text &&
                    text.endsWith("\r\n"),
            ) {
                "Held Dovecot seed message format is invalid"
            }
        }

        private fun abortAndClose(transport: DovecotOperatorTransport) {
            runCatching { transport.abort() }
            runCatching { transport.close() }
        }

        private inline fun <T> ByteArray.useWiped(
            block: (ByteArray) -> T,
        ): T = try {
            block(this)
        } finally {
            fill(0)
        }

        private fun ByteArray.hasAsciiTokenAt(
            offset: Int,
            token: String,
        ): Boolean {
            if (
                offset < 0 ||
                size < offset + token.length ||
                (offset > 0 && this[offset - 1] != ' '.code.toByte())
            ) {
                return false
            }
            token.indices.forEach { index ->
                if (this[offset + index] != token[index].code.toByte()) {
                    return false
                }
            }
            val end = offset + token.length
            return end == size || this[end] == ' '.code.toByte()
        }

        private const val SESSION_DEADLINE_NANOS = 5_000_000_000L
        private const val MAX_LINE_BYTES = 16 * 1024
        private const val MAX_RESPONSE_LINES = 64
        private const val MAX_AUTH_RESPONSE_BYTES = 1024
        private const val MAX_MESSAGE_BYTES = 16 * 1024
        private const val USABILITY_NOOP_TAG = "A003"
        private val REQUIRED_MESSAGE_HEADERS = listOf(
            "From",
            "To",
            "Date",
            "Subject",
            "Message-ID",
            "MIME-Version",
            "Content-Type",
        )
        private val AUTHENTICATE_LOGIN_COMMAND =
            "A001 AUTHENTICATE LOGIN\r\n".toByteArray(
                StandardCharsets.US_ASCII,
            )
        private val USERNAME_CHALLENGE =
            "+ VXNlcm5hbWU6".toByteArray(StandardCharsets.US_ASCII)
        private val PASSWORD_CHALLENGE =
            "+ UGFzc3dvcmQ6".toByteArray(StandardCharsets.US_ASCII)
        private val USABILITY_NOOP_COMMAND =
            "$USABILITY_NOOP_TAG NOOP\r\n".toByteArray(
                StandardCharsets.US_ASCII,
            )
        private val CLOSED_SESSION_NOOP_COMMAND =
            "A099 NOOP\r\n".toByteArray(StandardCharsets.US_ASCII)
        private val CRLF =
            "\r\n".toByteArray(StandardCharsets.US_ASCII)
    }
}
