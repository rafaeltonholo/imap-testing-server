package mail.sandbox.dashboard.server.gate.dovecot

import java.io.ByteArrayInputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

internal interface Task6DisposableEligibilityGateway {
    fun contains(candidate: String): Boolean

    fun add(
        candidate: String,
        password: EligibilityPassword,
    ): Int

    fun remove(candidate: String): Int
}

internal class Task6DisposableEligibilityFixture(
    private val address: String,
    private val passwordFactory: () -> EligibilityPassword,
    private val gateway: Task6DisposableEligibilityGateway,
    private val rejectionProof: () -> Unit,
) {
    var addAttempted: Boolean = false
        private set

    fun <T> run(block: (EligibilityPassword) -> T): T {
        var primaryFailure: Throwable? = null
        return try {
            check(!gateway.contains(address)) {
                "Disposable Dovecot eligibility target unexpectedly exists"
            }
            passwordFactory().use { password ->
                addAttempted = true
                check(gateway.add(address, password) == 0) {
                    "Disposable Dovecot eligibility add failed"
                }
                block(password)
            }
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            cleanupAfterAddAttempt(primaryFailure)
        }
    }

    private fun cleanupAfterAddAttempt(primaryFailure: Throwable?) {
        if (!addAttempted) return
        var cleanupFailure: Throwable? = null

        fun attempt(block: () -> Unit) {
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

        attempt {
            if (gateway.contains(address)) {
                check(gateway.remove(address) == 0) {
                    "Disposable Dovecot eligibility cleanup failed"
                }
            }
        }
        attempt(rejectionProof)

        cleanupFailure?.let { failure ->
            if (primaryFailure != null) {
                if (primaryFailure !== failure) {
                    primaryFailure.addSuppressed(failure)
                }
            } else {
                throw failure
            }
        }
    }
}

internal fun task6DisposableEligibilityFixture(
    address: String,
    paths: EligibilityPaths,
    executor: EligibilityCommandExecutor,
    rejectionProof: () -> Unit,
): Task6DisposableEligibilityFixture =
    Task6DisposableEligibilityFixture(
        address = address,
        passwordFactory = ::generateTask6DisposableEligibilityPassword,
        gateway = Task6CliDisposableEligibilityGateway(paths, executor),
        rejectionProof = rejectionProof,
    )

private class Task6CliDisposableEligibilityGateway(
    private val paths: EligibilityPaths,
    private val executor: EligibilityCommandExecutor,
) : Task6DisposableEligibilityGateway {
    override fun contains(candidate: String): Boolean =
        candidate in EligibilityFile(paths).list()

    override fun add(
        candidate: String,
        password: EligibilityPassword,
    ): Int {
        var input = ByteArray(0)
        return try {
            password.withBytes { bytes ->
                input = ByteArray(bytes.size + 1)
                bytes.copyInto(input)
                input[input.lastIndex] = '\n'.code.toByte()
            }
            execute(arrayOf("add", candidate), input)
        } finally {
            input.fill(0)
        }
    }

    override fun remove(candidate: String): Int =
        execute(arrayOf("remove", candidate), ByteArray(0))

    private fun execute(
        args: Array<String>,
        stdin: ByteArray,
    ): Int {
        val sink = PrintStream(
            OutputStream.nullOutputStream(),
            true,
            StandardCharsets.UTF_8,
        )
        return sink.use { output ->
            executor.execute(
                args = args,
                stdin = ByteArrayInputStream(stdin),
                stdout = output,
                stderr = output,
            )
        }
    }
}

private fun generateTask6DisposableEligibilityPassword(): EligibilityPassword {
    val bytes = ByteArray(TASK6_TARGET_PASSWORD_BYTES)
    return try {
        bytes.indices.forEach { index ->
            bytes[index] = TASK6_TARGET_PASSWORD_ALPHABET[
                TASK6_SECURE_RANDOM.nextInt(
                    TASK6_TARGET_PASSWORD_ALPHABET.length,
                )
            ].code.toByte()
        }
        EligibilityPassword.takeOwnership(bytes)
    } catch (failure: Throwable) {
        bytes.fill(0)
        throw failure
    }
}

private const val TASK6_TARGET_PASSWORD_BYTES = 48
private const val TASK6_TARGET_PASSWORD_ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
private val TASK6_SECURE_RANDOM = SecureRandom()
