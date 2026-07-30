package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DovecotOperatorStartupLiveTest {
    @Test
    fun isolatedTopologySupportsMasterLoginForAnEligibleDisposableTarget() {
        val repositoryRoot = repositoryRoot()
        val live = DovecotLiveTestEnvironment.load(
            environment = System.getenv(),
            repositoryRoot = repositoryRoot,
        )
        live.awaitReady()

        val address = disposableTargetAddress()
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
        val credentialStore = DovecotOperatorCredentialStore(
            paths = live.profile.operatorPaths(),
            hasher = DovecotOperatorHashBoundary {
                error("startup proof must not hash operator credentials")
            },
            verifier = ExistingDovecotOperatorHashVerifier(
                repositoryRoot,
                JvmEligibilityProcessRunner(
                    dockerRouting =
                        DovecotDockerRouting.task5Proof(live.profile),
                ),
            ),
            generator = DovecotOperatorSecretGenerator {
                error("startup proof must not bootstrap operator credentials")
            },
        )
        val probe = DovecotOperatorProbe(
            transportFactory =
                JvmJsseDovecotOperatorTransportFactory.task5Proof(
                    live.profile,
                ),
        )
        var addAttempted = false
        var primaryFailure: Throwable? = null
        try {
            require(address !in EligibilityFile(eligibilityPaths).list()) {
                "Disposable proof target unexpectedly exists"
            }
            addAttempted = true
            val credentialBuffers = mutableListOf<ByteArray>()
            try {
                generateTargetPassword(credentialBuffers).use { targetPassword ->
                    addEligibleTarget(
                        cli = eligibilityCli,
                        address = address,
                        targetPassword = targetPassword,
                        retainedBuffers = credentialBuffers,
                    )
                    assertEligibleTargetPasswordRejected(
                        live = live,
                        target = target,
                        targetPassword = targetPassword,
                        retainedBuffers = credentialBuffers,
                    )
                }
            } finally {
                assertTrue(
                    credentialBuffers.all { bytes ->
                        bytes.all { it == 0.toByte() }
                    },
                    "Bare-target LOGIN proof retained credential-bearing bytes",
                )
            }

            val plainAuthzidBuffers = mutableListOf<ByteArray>()
            try {
                assertPlainAuthzidMasterFormRejected(
                    live = live,
                    target = target,
                    credential = credentialStore.loadActive(),
                    retainedBuffers = plainAuthzidBuffers,
                )
            } finally {
                assertTrue(
                    plainAuthzidBuffers.all { bytes ->
                        bytes.all { it == 0.toByte() }
                    },
                    "PLAIN authzid proof retained credential-bearing bytes",
                )
            }
            val credential = credentialStore.loadActive()
            val result = probe.probe(target, credential)

            assertEquals(DovecotOperatorProbeResult.Success, result)
            live.awaitReady(maxAttempts = 3, delayMillis = 100)
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            try {
                if (
                    addAttempted &&
                    address in EligibilityFile(eligibilityPaths).list()
                ) {
                    removeEligibleTarget(eligibilityCli, address)
                }
                if (addAttempted) {
                    awaitDovecotOperatorTargetRejection(
                        resultSupplier = {
                            probe.probe(
                                target,
                                credentialStore.loadActive(),
                            )
                        },
                    )
                }
            } catch (cleanupFailure: Throwable) {
                val primary = primaryFailure
                if (primary != null) {
                    primary.addSuppressed(cleanupFailure)
                } else {
                    throw cleanupFailure
                }
            }
        }
    }

    private fun assertEligibleTargetPasswordRejected(
        live: DovecotLiveTestEnvironment,
        target: DovecotOperatorTarget,
        targetPassword: EligibilityPassword,
        retainedBuffers: MutableList<ByteArray>,
    ) {
        var transport: DovecotOperatorTransport? = null
        val targetBytes = target.address.toByteArray(StandardCharsets.US_ASCII)
        val authenticateCommand = AUTHENTICATE_LOGIN_COMMAND.copyOf()
        retainedBuffers += targetBytes
        retainedBuffers += authenticateCommand
        try {
            val opened =
                JvmJsseDovecotOperatorTransportFactory.task5Proof(
                    live.profile,
                ).open { allocated ->
                    check(transport == null)
                    transport = allocated
                }
            readBoundedLiveLine(opened.input).useBytes { greeting ->
                assertTrue(greeting.startsWithAscii("* OK"))
            }
            opened.outputStream.write(
                authenticateCommand,
                0,
                authenticateCommand.size,
            )
            opened.outputStream.flush()
            requireLiveContinuation(
                input = opened.input,
                expected = USERNAME_CHALLENGE,
            )
            writeBase64CredentialResponse(
                output = opened.outputStream,
                raw = targetBytes,
                retainedBuffers = retainedBuffers,
            )
            requireLiveContinuation(
                input = opened.input,
                expected = PASSWORD_CHALLENGE,
            )
            targetPassword.withBytes { passwordBytes ->
                writeBase64CredentialResponse(
                    output = opened.outputStream,
                    raw = passwordBytes,
                    retainedBuffers = retainedBuffers,
                )
            }
            readBoundedLiveLine(opened.input).useBytes { completion ->
                assertTrue(
                    completion.startsWithAscii("A901 NO"),
                    "Operator endpoint accepted bare-target SASL LOGIN",
                )
            }
        } finally {
            targetBytes.fill(0)
            authenticateCommand.fill(0)
            transport?.let { opened ->
                runCatching { opened.abort() }
                runCatching { opened.close() }
            }
        }
    }

    private fun requireLiveContinuation(
        input: InputStream,
        expected: ByteArray,
    ) {
        readBoundedLiveLine(input).useBytes { continuation ->
            assertTrue(
                continuation.contentEquals(expected),
                "Operator LOGIN challenge was invalid",
            )
        }
    }

    private fun writeBase64CredentialResponse(
        output: OutputStream,
        raw: ByteArray,
        retainedBuffers: MutableList<ByteArray>,
    ) {
        var encoded = ByteArray(0)
        var command = ByteArray(0)
        try {
            encoded = Base64.getEncoder().encode(raw)
            retainedBuffers += encoded
            command = ByteArray(encoded.size + COMMAND_SUFFIX.size)
            retainedBuffers += command
            encoded.copyInto(command)
            COMMAND_SUFFIX.copyInto(
                command,
                destinationOffset = encoded.size,
            )
            output.write(command, 0, command.size)
            output.flush()
        } finally {
            encoded.fill(0)
            command.fill(0)
        }
    }

    private fun assertPlainAuthzidMasterFormRejected(
        live: DovecotLiveTestEnvironment,
        target: DovecotOperatorTarget,
        credential: DovecotOperatorCredential,
        retainedBuffers: MutableList<ByteArray>,
    ) {
        var transport: DovecotOperatorTransport? = null
        val targetBytes = target.address.toByteArray(StandardCharsets.US_ASCII)
        val masterBytes =
            credential.id.masterUsername.toByteArray(StandardCharsets.US_ASCII)
        var plainPayload = ByteArray(0)
        var encodedPayload = ByteArray(0)
        var command = ByteArray(0)
        retainedBuffers += targetBytes
        retainedBuffers += masterBytes
        try {
            val opened =
                JvmJsseDovecotOperatorTransportFactory.task5Proof(
                    live.profile,
                ).open { allocated ->
                    check(transport == null)
                    transport = allocated
                }
            readBoundedLiveLine(opened.input).useBytes { greeting ->
                assertTrue(greeting.startsWithAscii("* OK"))
            }
            opened.outputStream.write(
                CAPABILITY_COMMAND,
                0,
                CAPABILITY_COMMAND.size,
            )
            opened.outputStream.flush()
            assertLoginOnlyCapability(
                input = opened.input,
            )
            credential.withSecretBytes { secret ->
                retainedBuffers += secret
                plainPayload = ByteArray(
                    targetBytes.size +
                        1 +
                        masterBytes.size +
                        1 +
                        secret.size,
                )
                retainedBuffers += plainPayload
                var offset = 0
                targetBytes.copyInto(
                    plainPayload,
                    destinationOffset = offset,
                )
                offset += targetBytes.size + 1
                masterBytes.copyInto(
                    plainPayload,
                    destinationOffset = offset,
                )
                offset += masterBytes.size + 1
                secret.copyInto(
                    plainPayload,
                    destinationOffset = offset,
                )

                encodedPayload = Base64.getEncoder().encode(plainPayload)
                retainedBuffers += encodedPayload
                command = ByteArray(
                    PLAIN_AUTH_PREFIX.size +
                        encodedPayload.size +
                        COMMAND_SUFFIX.size,
                )
                retainedBuffers += command
                PLAIN_AUTH_PREFIX.copyInto(command)
                encodedPayload.copyInto(
                    command,
                    destinationOffset = PLAIN_AUTH_PREFIX.size,
                )
                COMMAND_SUFFIX.copyInto(
                    command,
                    destinationOffset =
                        PLAIN_AUTH_PREFIX.size + encodedPayload.size,
                )
                opened.outputStream.write(command, 0, command.size)
                opened.outputStream.flush()
            }
            readBoundedLiveLine(opened.input).useBytes { completion ->
                assertTrue(
                    completion.startsWithAscii("A900 NO") ||
                        completion.startsWithAscii("A900 BAD"),
                    "Operator endpoint accepted SASL PLAIN authzid master form",
                )
                assertTrue(
                    !completion.containsBytes(encodedPayload),
                    "Operator rejection echoed credential-bearing bytes",
                )
            }
        } finally {
            credential.close()
            targetBytes.fill(0)
            masterBytes.fill(0)
            plainPayload.fill(0)
            encodedPayload.fill(0)
            command.fill(0)
            transport?.let { opened ->
                runCatching { opened.abort() }
                runCatching { opened.close() }
            }
        }
    }

    private fun assertLoginOnlyCapability(input: InputStream) {
        var sawCapability = false
        repeat(MAX_CAPABILITY_LINES) {
            readBoundedLiveLine(input).useBytes { line ->
                when {
                    line.startsWithAscii("* CAPABILITY") -> {
                        sawCapability = true
                        assertTrue(
                            line.hasAsciiToken("AUTH=LOGIN"),
                            "Operator endpoint did not advertise AUTH=LOGIN",
                        )
                        assertTrue(
                            !line.hasAsciiToken("AUTH=PLAIN"),
                            "Operator endpoint advertised forbidden AUTH=PLAIN",
                        )
                    }
                    line.startsWithAscii("A899 OK") -> {
                        assertTrue(
                            sawCapability,
                            "Operator CAPABILITY response was incomplete",
                        )
                        return
                    }
                    line.startsWithAscii("A899 NO") ||
                        line.startsWithAscii("A899 BAD") ->
                        error("Operator CAPABILITY command failed")
                }
            }
        }
        error("Operator CAPABILITY response exceeded its line bound")
    }

    private fun readBoundedLiveLine(input: InputStream): ByteArray {
        val buffer = ByteArray(MAX_LIVE_LINE_BYTES + 1)
        var size = 0
        try {
            while (true) {
                val value = input.read()
                check(value >= 0) { "Operator proof response ended early" }
                if (value == '\n'.code) {
                    check(
                        size > 0 &&
                            buffer[size - 1] == '\r'.code.toByte(),
                    ) {
                        "Operator proof response was malformed"
                    }
                    return buffer.copyOf(size - 1)
                }
                check(size < MAX_LIVE_LINE_BYTES) {
                    "Operator proof response exceeded its bound"
                }
                buffer[size] = value.toByte()
                size += 1
            }
        } finally {
            buffer.fill(0)
        }
    }

    private fun ByteArray.startsWithAscii(prefix: String): Boolean {
        val prefixBytes = prefix.toByteArray(StandardCharsets.US_ASCII)
        return try {
            size >= prefixBytes.size &&
                prefixBytes.indices.all { index ->
                    this[index] == prefixBytes[index]
                } &&
                (
                    size == prefixBytes.size ||
                        this[prefixBytes.size] == ' '.code.toByte()
                    )
        } finally {
            prefixBytes.fill(0)
        }
    }

    private fun ByteArray.hasAsciiToken(token: String): Boolean {
        val tokenBytes = token.toByteArray(StandardCharsets.US_ASCII)
        return try {
            if (tokenBytes.isEmpty() || tokenBytes.size > size) {
                false
            } else {
                (0..size - tokenBytes.size).any { offset ->
                    (offset == 0 || this[offset - 1] == ' '.code.toByte()) &&
                        (
                            offset + tokenBytes.size == size ||
                                this[offset + tokenBytes.size] ==
                                ' '.code.toByte()
                            ) &&
                        tokenBytes.indices.all { index ->
                            this[offset + index].asciiUppercase() ==
                                tokenBytes[index].asciiUppercase()
                        }
                }
            }
        } finally {
            tokenBytes.fill(0)
        }
    }

    private fun Byte.asciiUppercase(): Byte =
        if (this in 'a'.code.toByte()..'z'.code.toByte()) {
            (toInt() - ASCII_CASE_OFFSET).toByte()
        } else {
            this
        }

    private fun ByteArray.containsBytes(candidate: ByteArray): Boolean {
        if (candidate.isEmpty() || candidate.size > size) return false
        return (0..size - candidate.size).any { offset ->
            candidate.indices.all { index ->
                this[offset + index] == candidate[index]
            }
        }
    }

    private inline fun <T> ByteArray.useBytes(
        block: (ByteArray) -> T,
    ): T = try {
        block(this)
    } finally {
        fill(0)
    }

    private fun generateTargetPassword(
        retainedBuffers: MutableList<ByteArray>,
    ): EligibilityPassword {
        val password = ByteArray(TARGET_PASSWORD_BYTES)
        retainedBuffers += password
        try {
            repeat(TARGET_PASSWORD_BYTES) { index ->
                password[index] = TARGET_PASSWORD_ALPHABET_BYTES[
                    SECURE_RANDOM.nextInt(TARGET_PASSWORD_ALPHABET_BYTES.size)
                ]
            }
            return EligibilityPassword.takeOwnership(password)
        } catch (failure: Throwable) {
            password.fill(0)
            throw failure
        }
    }

    private fun addEligibleTarget(
        cli: EligibilityFileCli,
        address: String,
        targetPassword: EligibilityPassword,
        retainedBuffers: MutableList<ByteArray>,
    ) {
        var input = ByteArray(0)
        try {
            targetPassword.withBytes { passwordBytes ->
                input = ByteArray(passwordBytes.size + 1)
                retainedBuffers += input
                passwordBytes.copyInto(input)
                input[input.lastIndex] = '\n'.code.toByte()
            }
            assertEquals(
                0,
                executeEligibility(
                    cli = cli,
                    args = arrayOf("add", address),
                    stdin = input,
                ),
                "Disposable eligibility add failed",
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
                cli = cli,
                args = arrayOf("remove", address),
                stdin = ByteArray(0),
            ),
            "Disposable eligibility cleanup failed",
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

    private fun disposableTargetAddress(): String =
        "task5-proof-" +
            UUID.randomUUID().toString().replace("-", "") +
            "@local.test"

    private fun repositoryRoot(): Path {
        val workingDirectory = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
        val dashboardRoot = if (
            workingDirectory.fileName?.toString() == "dashboard-server"
        ) {
            requireNotNull(workingDirectory.parent)
        } else {
            workingDirectory
        }
        return requireNotNull(dashboardRoot.parent).also { root ->
            require(Files.isRegularFile(root.resolve("docker-compose.yml")))
        }
    }

    companion object {
        private const val TARGET_PASSWORD_BYTES = 48
        private const val TARGET_PASSWORD_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
        private val TARGET_PASSWORD_ALPHABET_BYTES =
            TARGET_PASSWORD_ALPHABET.toByteArray(StandardCharsets.US_ASCII)
        private val SECURE_RANDOM = SecureRandom()
        private const val MAX_LIVE_LINE_BYTES = 16 * 1024
        private const val MAX_CAPABILITY_LINES = 32
        private const val ASCII_CASE_OFFSET = 'a'.code - 'A'.code
        private val CAPABILITY_COMMAND =
            "A899 CAPABILITY\r\n".toByteArray(StandardCharsets.US_ASCII)
        private val AUTHENTICATE_LOGIN_COMMAND =
            "A901 AUTHENTICATE LOGIN\r\n"
                .toByteArray(StandardCharsets.US_ASCII)
        private val USERNAME_CHALLENGE =
            "+ VXNlcm5hbWU6".toByteArray(StandardCharsets.US_ASCII)
        private val PASSWORD_CHALLENGE =
            "+ UGFzc3dvcmQ6".toByteArray(StandardCharsets.US_ASCII)
        private val PLAIN_AUTH_PREFIX =
            "A900 AUTHENTICATE PLAIN "
                .toByteArray(StandardCharsets.US_ASCII)
        private val COMMAND_SUFFIX =
            "\r\n".toByteArray(StandardCharsets.US_ASCII)
    }
}
