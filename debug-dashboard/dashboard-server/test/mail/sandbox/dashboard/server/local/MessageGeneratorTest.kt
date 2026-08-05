package mail.sandbox.dashboard.server.local

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import mail.sandbox.dashboard.contract.GenerateMessageRequest
import mail.sandbox.dashboard.contract.MessageSourceType
import mail.sandbox.dashboard.contract.Provider

class MessageGeneratorTest {
    private val generator = MessageGenerator()

    @Test
    fun preservesUploadedEmlAndCreatesRequestedCopies() {
        val eml = "From: sender@local.test\r\nTo: alice@local.test\r\n\r\nHello\r\n"

        val generated = generator.generate(
            GenerateMessageRequest(
                targetAccount = "alice@local.test",
                provider = Provider.DOVECOT,
                sourceType = MessageSourceType.EML,
                content = eml,
                count = 2,
            ),
        )

        assertEquals(listOf(eml, eml), generated.map(GeneratedMessage::rawEml))
    }

    @Test
    fun authoredTextBecomesACompleteRfcMessage() {
        val message = generator.generate(
            GenerateMessageRequest(
                targetAccount = "alice@local.test",
                provider = Provider.STALWART,
                sourceType = MessageSourceType.TEXT,
                content = "Reproduction steps\nSecond line",
                subject = "Client bug",
                fromAddress = "sender@local.test",
            ),
        ).single().rawEml

        assertTrue("From: sender@local.test\r\n" in message)
        assertTrue("To: alice@local.test\r\n" in message)
        assertTrue("Subject: Client bug\r\n" in message)
        assertTrue("Content-Type: text/plain; charset=UTF-8\r\n" in message)
        assertTrue(message.endsWith("Reproduction steps\r\nSecond line\r\n"))
    }

    @Test
    fun randomGenerationIsRepeatableForASeedAndVariesPerMessage() {
        val request = GenerateMessageRequest(
            targetAccount = "alice@local.test",
            provider = Provider.DOVECOT,
            sourceType = MessageSourceType.RANDOM,
            seed = 42,
            count = 3,
        )

        val first = generator.generate(request).map(GeneratedMessage::rawEml)
        val second = generator.generate(request).map(GeneratedMessage::rawEml)

        assertEquals(first, second)
        assertEquals(3, first.toSet().size)
        assertTrue(first.all { "X-Dashboard-Seed: 42" in it })
    }

    @Test
    fun rejectsHeaderInjectionInvalidTargetsAndUnboundedCounts() {
        assertFailsWith<IllegalArgumentException> {
            generator.generate(
                GenerateMessageRequest(
                    targetAccount = "outside@example.com",
                    provider = Provider.DOVECOT,
                    sourceType = MessageSourceType.TEXT,
                    content = "body",
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            generator.generate(
                GenerateMessageRequest(
                    targetAccount = "alice@local.test",
                    provider = Provider.DOVECOT,
                    sourceType = MessageSourceType.TEXT,
                    content = "body",
                    subject = "bad\r\nBcc: victim@local.test",
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            generator.generate(
                GenerateMessageRequest(
                    targetAccount = "alice@local.test",
                    provider = Provider.DOVECOT,
                    sourceType = MessageSourceType.RANDOM,
                    count = 101,
                ),
            )
        }
    }
}
