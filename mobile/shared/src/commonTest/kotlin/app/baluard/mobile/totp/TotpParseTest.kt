package app.baluard.mobile.totp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** TOTP wire response parsing: the runtime returns JSON, not the legacy
 * "<code> <secs>" space form; the code must render, not the raw JSON. */
class TotpParseTest {

    @Test
    fun parsesJsonResponse() {
        val (code, secs, period) = parseTotpResponse(
            """{"code":"123456","period_seconds":30,"expires_at":1000000025}""",
            epochSeconds = 100_000_0000L,
        )!!
        assertEquals("123456", code)
        assertEquals(25, secs)
        assertEquals(30, period)
    }

    @Test
    fun clampsExpiredWindowToZero() {
        val (code, secs) = parseTotpResponse(
            """{"code":"123456","period_seconds":30,"expires_at":1000000000}""",
            epochSeconds = 100_000_0010L,
        )!!
        assertEquals("123456", code)
        assertEquals(0, secs)
    }

    @Test
    fun acceptsLegacySpaceForm() {
        val (code, secs) = parseTotpResponse("654321 12", epochSeconds = 7L)!!
        assertEquals("654321", code)
        assertEquals(12, secs)
    }

    @Test
    fun jsonWithoutCodeIsNull() {
        assertNull(parseTotpResponse("""{"period_seconds":30}""", epochSeconds = 7L))
    }

    @Test
    fun garbageIsNull() {
        assertNull(parseTotpResponse("not totp", epochSeconds = 7L))
    }

    @Test
    fun sixtySecondPeriodScalesTheWindow() {
        val (_, secs, period) = parseTotpResponse(
            """{"code":"123456","period_seconds":60,"expires_at":1000000040}""",
            epochSeconds = 100_000_0000L,
        )!!
        assertEquals(40, secs)
        assertEquals(60, period)
    }

    @Test
    fun jsonCodeRendersNotRawJson() {
        // Regression: the old parser looked for an all-digit space token, so a
        // JSON body fell through and would have rendered the raw JSON.
        val r = parseTotpResponse(
            """{"code":"987654","period_seconds":30,"expires_at":1000000010}""",
            epochSeconds = 100_000_0000L,
        )!!
        assertTrue(r.first.all(Char::isDigit) && r.first.length == 6)
    }
}
