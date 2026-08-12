package mail.sandbox.dashboard.server.local

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DovecotMimeParserTest {
    @Test
    fun unfoldsHeadersAndDecodesQuotedPrintableIso88591Text() {
        val raw = lines(
            "Subject: A folded",
            "\tdebugging subject",
            "To: alice@local.test,",
            " bob@local.test",
            "Content-Type: text/plain;",
            " charset=ISO-8859-1",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "Ol=E1, equipe!=0Asoft=20line=",
            "continued",
        )

        val parsed = DovecotMimeParser.parse(raw)

        assertEquals("A folded debugging subject", parsed.header("subject"))
        assertEquals(
            "alice@local.test, bob@local.test",
            parsed.header("to"),
        )
        assertEquals("Olá, equipe!\nsoft linecontinued", parsed.textBody)
        assertNull(parsed.htmlBody)
    }

    @Test
    fun extractsPlainAndHtmlBodiesFromMultipartAlternative() {
        val raw = lines(
            "MIME-Version: 1.0",
            "Content-Type: multipart/alternative;",
            " boundary=\"dashboard-boundary\"",
            "",
            "--dashboard-boundary",
            "Content-Type: text/plain; charset=UTF-8",
            "Content-Transfer-Encoding: base64",
            "",
            "T2zDoSwgZGVidWdnZXIh",
            "--dashboard-boundary",
            "Content-Type: text/html; charset=US-ASCII",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<p>Ol=26aacute; from <strong>Dovecot</strong></p>",
            "--dashboard-boundary--",
            "",
        )

        val parsed = DovecotMimeParser.parse(raw)

        assertEquals("Olá, debugger!", parsed.textBody)
        assertEquals(
            "<p>Ol&aacute; from <strong>Dovecot</strong></p>",
            parsed.htmlBody,
        )
    }

    @Test
    fun findsTextBodiesInsideNestedMultipartMessages() {
        val raw = lines(
            "Content-Type: multipart/mixed; boundary=outer",
            "",
            "preamble used by the sending provider",
            "--outer",
            "Content-Type: application/json",
            "",
            "{\"provider\":\"dovecot\"}",
            "--outer",
            "Content-Type: multipart/alternative; boundary=inner",
            "",
            "--inner",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "nested plain",
            "--inner",
            "Content-Type: text/html; charset=utf-8",
            "",
            "<p>nested html</p>",
            "--inner--",
            "--outer--",
        )

        val parsed = DovecotMimeParser.parse(raw)

        assertEquals("nested plain", parsed.textBody)
        assertEquals("<p>nested html</p>", parsed.htmlBody)
    }

    @Test
    fun returnsTheRawPartBodyWhenBase64IsMalformed() {
        val raw = lines(
            "Content-Type: text/plain; charset=UTF-8",
            "Content-Transfer-Encoding: base64",
            "",
            "not-valid-base64%%%",
        )

        val parsed = DovecotMimeParser.parse(raw)

        assertEquals("not-valid-base64%%%", parsed.textBody)
        assertNull(parsed.htmlBody)
    }

    @Test
    fun returnsTheRawPartBodyWhenCharsetIsUnsupported() {
        val raw = lines(
            "Content-Type: text/html; charset=KOI8-R",
            "Content-Transfer-Encoding: quoted-printable",
            "",
            "<p>=F0=D2=C9=D7=C5=D4</p>",
        )

        val parsed = DovecotMimeParser.parse(raw)

        assertEquals("<p>=F0=D2=C9=D7=C5=D4</p>", parsed.textBody)
        assertNull(parsed.htmlBody)
    }

    @Test
    fun returnsTheRawMultipartBodyWhenItsBoundaryIsMissing() {
        val rawBody = lines(
            "This message says it is multipart but has no boundary parameter.",
            "Its body must stay visible for debugging.",
        )
        val raw = lines(
            "Content-Type: multipart/alternative",
            "",
            rawBody,
        )

        val parsed = DovecotMimeParser.parse(raw)

        assertEquals(rawBody, parsed.textBody)
        assertNull(parsed.htmlBody)
    }

    @Test
    fun boundsMultipartTraversalAndKeepsUnparsedContentVisible() {
        val parts = (1..300).joinToString("\r\n") { index ->
            lines(
                "--many",
                "Content-Type: text/plain",
                "",
                "part-$index",
            )
        }
        val raw = lines(
            "Content-Type: multipart/mixed; boundary=many",
            "",
            parts,
            "--many--",
        )

        val parsed = DovecotMimeParser.parse(raw)

        assertTrue(parsed.textBody.orEmpty().contains("part-300"))
    }

    @Test
    fun skipsAnAttachmentLargerThanTheFormerReaderLimitAndKeepsTheTextBody() {
        val attachmentPayload = "A".repeat(9 * 1024 * 1024)
        val raw = lines(
            "Content-Type: multipart/mixed; boundary=large",
            "",
            "--large",
            "Content-Type: text/plain; charset=utf-8",
            "",
            "visible debugging body",
            "--large",
            "Content-Type: application/octet-stream",
            "Content-Disposition: attachment; filename=fixture.bin",
            "Content-Transfer-Encoding: base64",
            "",
            attachmentPayload,
            "--large--",
        )

        val parsed = DovecotMimeParser.parse(raw)

        assertEquals("visible debugging body", parsed.textBody)
        assertNull(parsed.htmlBody)
        assertTrue(attachmentPayload !in parsed.textBody.orEmpty())
    }

    private fun lines(vararg values: String): String = values.joinToString("\r\n")
}
