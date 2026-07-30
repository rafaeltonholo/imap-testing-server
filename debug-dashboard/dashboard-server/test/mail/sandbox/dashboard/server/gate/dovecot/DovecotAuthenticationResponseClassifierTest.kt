package mail.sandbox.dashboard.server.gate.dovecot

import java.nio.charset.StandardCharsets
import kotlin.test.Test
import kotlin.test.assertEquals

class DovecotAuthenticationResponseClassifierTest {
    @Test
    fun imapRequiresTheExactTaggedPermanentAuthenticationFailureCode() {
        val cases = mapOf(
            "A601 OK authenticated" to
                DovecotAuthenticationResponse.Success,
            "A601 NO [AUTHENTICATIONFAILED] Authentication failed." to
                DovecotAuthenticationResponse.PermanentFailure,
            "A601 NO [UNAVAILABLE] Authentication service unavailable." to
                DovecotAuthenticationResponse.Indeterminate,
            "A601 NO [SERVERBUG] Internal error." to
                DovecotAuthenticationResponse.Indeterminate,
            "A601 NO Authentication failed." to
                DovecotAuthenticationResponse.Indeterminate,
            "A601 NO [AUTHENTICATIONFAILED]" to
                DovecotAuthenticationResponse.Indeterminate,
            "A601 NO [AUTHENTICATIONFAILED extra] Authentication failed." to
                DovecotAuthenticationResponse.Indeterminate,
            "A601 NO [AUTHENTICATIONFAILED]Authentication failed." to
                DovecotAuthenticationResponse.Indeterminate,
            "A601 BAD [AUTHENTICATIONFAILED] malformed command" to
                DovecotAuthenticationResponse.Indeterminate,
            "A6010 NO [AUTHENTICATIONFAILED] wrong tag" to
                DovecotAuthenticationResponse.Indeterminate,
            "* NO [AUTHENTICATIONFAILED] untagged" to
                DovecotAuthenticationResponse.Indeterminate,
        )

        cases.forEach { (line, expected) ->
            assertEquals(
                expected,
                DovecotAuthenticationResponseClassifier.classifyImap(
                    line = line.toByteArray(StandardCharsets.US_ASCII),
                    tag = "A601".toByteArray(StandardCharsets.US_ASCII),
                ),
                line,
            )
        }
    }

    @Test
    fun pop3RequiresTheExactPermanentAuthenticationFailureCode() {
        val cases = mapOf(
            "+OK authenticated" to DovecotAuthenticationResponse.Success,
            "-ERR [AUTH] Authentication failed." to
                DovecotAuthenticationResponse.PermanentFailure,
            "-ERR [SYS/TEMP] Authentication service unavailable." to
                DovecotAuthenticationResponse.Indeterminate,
            "-ERR Authentication failed." to
                DovecotAuthenticationResponse.Indeterminate,
            "-ERR [AUTH]" to DovecotAuthenticationResponse.Indeterminate,
            "-ERR [AUTH extra] Authentication failed." to
                DovecotAuthenticationResponse.Indeterminate,
            "-ERR [AUTH]Authentication failed." to
                DovecotAuthenticationResponse.Indeterminate,
            "-ERR [AUTHENTICATIONFAILED] Authentication failed." to
                DovecotAuthenticationResponse.Indeterminate,
            "+OK [AUTH] misleading success" to
                DovecotAuthenticationResponse.Success,
        )

        cases.forEach { (line, expected) ->
            assertEquals(
                expected,
                DovecotAuthenticationResponseClassifier.classifyPop3(
                    line.toByteArray(StandardCharsets.US_ASCII),
                ),
                line,
            )
        }
    }
}
