package mail.sandbox.dashboard.server.gate.dovecot

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DovecotOAuthProofValidatorTest {
    @Test
    fun preInterruptedHttpProofFailsBeforeSocketAllocation() {
        val socketAllocations = AtomicInteger()
        var interruptPreserved = false

        try {
            Thread.currentThread().interrupt()
            assertFailsWith<InterruptedException> {
                DovecotBoundedHttpProofClient(
                    port = 1,
                    timeoutMillis = 1_000,
                    maximumResponseBytes = 1024,
                    socketFactory = {
                        socketAllocations.incrementAndGet()
                        Socket()
                    },
                ).postForm("/introspect", ByteArray(0))
            }
            interruptPreserved = Thread.currentThread().isInterrupted
        } finally {
            Thread.interrupted()
        }

        assertTrue(interruptPreserved)
        assertEquals(0, socketAllocations.get())
    }

    @Test
    fun midOperationHttpInterruptionEscapesAndPreservesStatus() {
        val caller = Thread.currentThread()
        var interruptPreserved = false

        withLoopbackHttpServer(
            responseWriter = { output ->
                caller.interrupt()
                output.write(
                    (
                        "HTTP/1.0 200 OK\r\n" +
                            "Content-Length: 0\r\n" +
                            "\r\n"
                        ).toByteArray(StandardCharsets.US_ASCII),
                )
                output.flush()
            },
        ) { port ->
            try {
                assertFailsWith<InterruptedException> {
                    DovecotBoundedHttpProofClient(
                        port = port,
                        timeoutMillis = 1_000,
                        maximumResponseBytes = 1024,
                    ).postForm("/introspect", ByteArray(0))
                }
                interruptPreserved =
                    Thread.currentThread().isInterrupted
            } finally {
                Thread.interrupted()
            }
        }

        assertTrue(interruptPreserved)
    }

    @Test
    fun inactiveProofRequiresAnActualJsonBooleanFalse() {
        DovecotOAuthProofValidator.requireInactive(
            """{"active":false}""".toByteArray(StandardCharsets.UTF_8),
        )

        listOf(
            """{"active":"false"}""",
            """{"active":true}""",
            """{"active":0}""",
            """{"active":null}""",
            """{"active":false,"active":false}""",
            """{"\u0061ctive":true,"active":false}""",
            """{"scope":"imap"}""",
            """[]""",
            """not-json""",
        ).forEach { body ->
            assertFailsWith<IllegalStateException>(body) {
                DovecotOAuthProofValidator.requireInactive(
                    body.toByteArray(StandardCharsets.UTF_8),
                )
            }
        }
    }

    @Test
    fun denialRedirectParsesPercentDecodedUniqueQueryFields() {
        listOf(
            "http://127.0.0.1/callback?error=access_denied&state=task6",
            "http://127.0.0.1/callback?state=task6&" +
                "err%6Fr=access%5Fdenied",
        ).forEach(
            DovecotOAuthProofValidator::requireAccessDeniedRedirect,
        )

        listOf(
            "http://127.0.0.1/callback?noterror=access_denied",
            "http://127.0.0.1/callback?error=access_denied_extra",
            "http://127.0.0.1/callback?error=access_denied&code=",
            "http://127.0.0.1/callback?code=hidden&error=access_denied",
            "http://127.0.0.1/callback?error=access_denied&" +
                "error=access_denied",
            "http://127.0.0.1/callback?state=one&state=two&" +
                "error=access_denied",
            "http://127.0.0.1/callback?error%3Daccess_denied",
            "http://127.0.0.1/callback?error=access+denied",
            "http://127.0.0.1/callback?error=access%GGdenied",
            "http://127.0.0.1/callback#?error=access_denied",
            "http://attacker.invalid/callback?error=access_denied&state=task6",
            "http://127.0.0.1/other?error=access_denied&state=task6",
            "http://127.0.0.1:80/callback?error=access_denied&state=task6",
            "http://user@127.0.0.1/callback?error=access_denied&state=task6",
            "/callback?error=access_denied&state=task6",
            "http://127.0.0.1/callback?error=access_denied",
            "http://127.0.0.1/callback?error=access_denied&state=other",
            "http://127.0.0.1/callback?error=access_denied&state=task6#" +
                "code=leaked",
        ).forEach { location ->
            assertFailsWith<IllegalStateException>(location) {
                DovecotOAuthProofValidator.requireAccessDeniedRedirect(
                    location,
                )
            }
        }
    }

    @Test
    fun oversizedHttpBodiesAreWipedBeforeRejection() {
        val oversized = ByteArray(9) { index -> (index + 1).toByte() }

        assertFailsWith<IllegalStateException> {
            task6RequireBoundedHttpBody(
                body = oversized,
                maximumBytes = 8,
            )
        }

        assertTrue(oversized.all { it == 0.toByte() })
    }

    @Test
    fun boundedHttpClientUsesOneDeadlineAcrossADripFedResponse() {
        withLoopbackHttpServer(
            responseWriter = { output ->
                output.write(
                    (
                        "HTTP/1.0 200 OK\r\n" +
                            "Content-Type: application/json\r\n" +
                            "\r\n"
                        ).toByteArray(StandardCharsets.US_ASCII),
                )
                output.flush()
                """{"active":false}"""
                    .toByteArray(StandardCharsets.US_ASCII)
                    .forEach { byte ->
                        output.write(byte.toInt())
                        output.flush()
                        Thread.sleep(25)
                    }
            },
        ) { port ->
            val started = System.nanoTime()

            assertFailsWith<IllegalStateException> {
                DovecotBoundedHttpProofClient(
                    port = port,
                    timeoutMillis = 80,
                    maximumResponseBytes = 1024,
                ).postForm("/introspect", ByteArray(0))
            }

            assertTrue(
                System.nanoTime() - started <
                    java.util.concurrent.TimeUnit.SECONDS.toNanos(1),
            )
        }
    }

    @Test
    fun boundedHttpClientRejectsOversizedOrExcessiveHeaders() {
        val oversizedLocation = (
            "http://127.0.0.1/callback?error=access_denied&state=" +
                "x".repeat(3_000)
            )
        val excessiveHeaders = buildString {
            append("HTTP/1.0 200 OK\r\n")
            repeat(40) { index ->
                append("X-Proof-$index: value\r\n")
            }
            append("\r\n")
        }
        listOf(
            "HTTP/1.0 302 Found\r\n" +
                "Location: $oversizedLocation\r\n" +
                "\r\n",
            excessiveHeaders,
        ).forEach { response ->
            withLoopbackHttpServer(
                responseWriter = { output ->
                    output.write(
                        response.toByteArray(StandardCharsets.US_ASCII),
                    )
                    output.flush()
                },
            ) { port ->
                assertFailsWith<IllegalStateException>(response.take(32)) {
                    DovecotBoundedHttpProofClient(
                        port = port,
                        timeoutMillis = 1_000,
                        maximumResponseBytes = 1024,
                    ).postForm("/authorize", ByteArray(0))
                }
            }
        }
    }

    @Test
    fun boundedHttpClientParsesFixedStatusLocationAndCloseDelimitedBody() {
        val expectedBody =
            """{"active":false}""".toByteArray(StandardCharsets.US_ASCII)
        withLoopbackHttpServer(
            responseWriter = { output ->
                output.write(
                    (
                        "HTTP/1.0 302 Found\r\n" +
                            "Location: http://127.0.0.1/callback?" +
                            "error=access_denied&state=task6\r\n" +
                            "\r\n"
                        ).toByteArray(StandardCharsets.US_ASCII),
                )
                output.write(expectedBody)
                output.flush()
            },
        ) { port ->
            DovecotBoundedHttpProofClient(
                port = port,
                timeoutMillis = 1_000,
                maximumResponseBytes = 1024,
            ).postForm("/authorize", ByteArray(0)).use { response ->
                assertEquals(302, response.status)
                assertEquals(
                    "http://127.0.0.1/callback?" +
                        "error=access_denied&state=task6",
                    response.location,
                )
                assertContentEquals(expectedBody, response.body)
            }
        }
    }

    @Test
    fun boundedHttpClientRejectsContentLengthBeyondASmallConfiguredLimit() {
        withLoopbackHttpServer(
            responseWriter = { output ->
                output.write(
                    (
                        "HTTP/1.0 200 OK\r\n" +
                            "Content-Length: 9\r\n" +
                            "\r\n" +
                            "123456789"
                        ).toByteArray(StandardCharsets.US_ASCII),
                )
                output.flush()
            },
        ) { port ->
            assertFailsWith<IllegalStateException> {
                DovecotBoundedHttpProofClient(
                    port = port,
                    timeoutMillis = 1_000,
                    maximumResponseBytes = 1,
                ).postForm("/introspect", ByteArray(0))
            }
        }
    }

    private fun <T> withLoopbackHttpServer(
        responseWriter: (OutputStream) -> Unit,
        block: (Int) -> T,
    ): T {
        val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        val server = ServerSocket(0, 1, loopback)
        val failure = AtomicReference<Throwable?>()
        val worker = thread(isDaemon = true, name = "task6-http-proof-server") {
            try {
                server.accept().use { socket ->
                    consumeRequestHeaders(socket.getInputStream())
                    responseWriter(socket.getOutputStream())
                }
            } catch (_: IOException) {
                // A deadline deliberately closes a drip-fed connection.
            } catch (unexpected: Throwable) {
                failure.set(unexpected)
            }
        }
        return try {
            block(server.localPort)
        } finally {
            server.close()
            worker.join(1_000)
            assertFalse(worker.isAlive)
            failure.get()?.let { throw it }
        }
    }

    private fun consumeRequestHeaders(input: InputStream) {
        var matched = 0
        repeat(8 * 1024) {
            val value = input.read()
            check(value >= 0) { "Task 6 HTTP test request ended early" }
            matched = if (value == HTTP_HEADER_END[matched].toInt()) {
                matched + 1
            } else if (value == HTTP_HEADER_END[0].toInt()) {
                1
            } else {
                0
            }
            if (matched == HTTP_HEADER_END.size) return
        }
        error("Task 6 HTTP test request headers exceeded their bound")
    }

    companion object {
        private val HTTP_HEADER_END =
            "\r\n\r\n".toByteArray(StandardCharsets.US_ASCII)
    }
}
