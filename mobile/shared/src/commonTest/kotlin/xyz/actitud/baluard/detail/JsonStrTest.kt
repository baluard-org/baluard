package xyz.actitud.baluard.detail

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** kotlinx JsonNull IS a JsonPrimitive whose content is the literal "null":
 * a plain `as? JsonPrimitive` cast turns every null field into "null" and
 * made non-TOTP entries render a failing TOTP card (hasTotp=true). */
class JsonStrTest {

    private fun obj(json: String): JsonObject =
        Json.parseToJsonElement(json) as JsonObject

    @Test
    fun nullTotpUriIsAbsentNotTheStringNull() {
        val o = obj("""{"totp_uri":null,"username":"me"}""")
        assertNull(o.str("totp_uri"))
        assertEquals("me", o.str("username"))
    }

    @Test
    fun missingKeyIsAbsent() {
        assertNull(obj("""{}""").str("totp_uri"))
    }

    @Test
    fun emptyStringStaysPresent() {
        // Callers decide blank handling; the helper only rules out JSON null.
        assertEquals("", obj("""{"totp_uri":""}""").str("totp_uri"))
    }
}
