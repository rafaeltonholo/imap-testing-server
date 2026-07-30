package mail.sandbox.dashboard.server.gate.dovecot

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

internal object DovecotOAuthProofValidator {
    fun requireInactive(body: ByteArray) {
        check(
            JSON_ESCAPE !in body &&
                body.countExactActiveKeys() == 1,
        ) {
            "OAuth introspection active field was not unique"
        }
        val document = try {
            Json.parseToJsonElement(body.toString(StandardCharsets.UTF_8))
        } catch (_: Exception) {
            error("OAuth introspection response was invalid")
        }
        val root = document as? JsonObject
        val active = root?.get("active") as? JsonPrimitive
        check(
            active != null &&
                !active.isString &&
                active.booleanOrNull == false,
        ) {
            "OAuth introspection response was not inactive"
        }
    }

    fun requireAccessDeniedRedirect(location: String) {
        val redirect = try {
            URI(location)
        } catch (_: Exception) {
            error("OAuth denial redirect was invalid")
        }
        check(
            redirect.scheme == CALLBACK_SCHEME &&
                redirect.rawAuthority == CALLBACK_AUTHORITY &&
                redirect.rawPath == CALLBACK_PATH &&
                redirect.rawFragment == null,
        ) {
            "OAuth denial redirect target was invalid"
        }
        val query = redirect.rawQuery
        check(!query.isNullOrEmpty()) {
            "OAuth denial redirect query was absent"
        }
        val fields = linkedMapOf<String, String>()
        query.split('&').forEach { field ->
            val separator = field.indexOf('=')
            check(
                separator > 0 &&
                    separator == field.lastIndexOf('='),
            ) {
                "OAuth denial redirect query was malformed"
            }
            val key = field.substring(0, separator).decodeQueryComponent()
            val value = field.substring(separator + 1).decodeQueryComponent()
            check(key.isNotEmpty() && fields.put(key, value) == null) {
                "OAuth denial redirect query keys were not unique"
            }
        }
        check(fields["error"] == "access_denied") {
            "OAuth denial redirect did not contain access_denied"
        }
        check(fields["state"] == CALLBACK_STATE) {
            "OAuth denial redirect did not preserve state"
        }
        check("code" !in fields) {
            "OAuth denial redirect contained an authorization code"
        }
    }

    private fun String.decodeQueryComponent(): String =
        try {
            URLDecoder.decode(this, StandardCharsets.UTF_8)
        } catch (_: IllegalArgumentException) {
            error("OAuth denial redirect encoding was invalid")
        }

    private fun ByteArray.countExactActiveKeys(): Int {
        var count = 0
        var offset = 0
        while (offset <= size - ACTIVE_KEY.size) {
            if (
                ACTIVE_KEY.indices.all { index ->
                    this[offset + index] == ACTIVE_KEY[index]
                }
            ) {
                count += 1
                offset += ACTIVE_KEY.size
            } else {
                offset += 1
            }
        }
        return count
    }

    private val ACTIVE_KEY =
        byteArrayOf(
            '"'.code.toByte(),
            'a'.code.toByte(),
            'c'.code.toByte(),
            't'.code.toByte(),
            'i'.code.toByte(),
            'v'.code.toByte(),
            'e'.code.toByte(),
            '"'.code.toByte(),
        )
    private const val CALLBACK_SCHEME = "http"
    private const val CALLBACK_AUTHORITY = "127.0.0.1"
    private const val CALLBACK_PATH = "/callback"
    private const val CALLBACK_STATE = "task6"
    private const val JSON_ESCAPE: Byte = 0x5c
}
