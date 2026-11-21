package app.baluard.mobile.platform

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

@OptIn(ExperimentalEncodingApi::class)
class SiteIconTest {

    private val pngBytes = byteArrayOf(
        0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3,
    )

    private fun faviconJson(mime: String, bytes: ByteArray): String =
        """{"name":"Example","kind":{"type":"login","data":{}},""" +
            """"favicon":{"data":"${Base64.encode(bytes)}","mime":"$mime"}}"""

    /** header(6) + one 16-byte entry pointing at [data] (offset 22). */
    private fun ico(entries: List<Pair<Int, ByteArray>>): ByteArray {
        val header = byteArrayOf(0, 0, 1, 0, entries.size.toByte(), 0)
        var offset = 6 + entries.size * 16
        var dir = header
        for ((size, _) in entries) {
            dir += byteArrayOf(
                32, 32, 0, 0, 1, 0, 32, 0,
                (size and 0xFF).toByte(), ((size shr 8) and 0xFF).toByte(), 0, 0,
                (offset and 0xFF).toByte(), ((offset shr 8) and 0xFF).toByte(), ((offset shr 16) and 0xFF).toByte(), 0,
            )
            offset += size
        }
        var body = dir
        for ((_, bytes) in entries) body += bytes
        return body
    }

    @Test
    fun extractsAllowlistedFavicon() {
        val bytes = SiteIcon.fromCipherJson(faviconJson("image/png", pngBytes))
        assertContentEquals(pngBytes, bytes)
    }

    @Test
    fun acceptsBothIcoMimeAliases() {
        val ico = ico(listOf(pngBytes.size to pngBytes))
        assertContentEquals(pngBytes, SiteIcon.fromCipherJson(faviconJson("image/x-icon", ico)))
        assertContentEquals(pngBytes, SiteIcon.fromCipherJson(faviconJson("image/vnd.microsoft.icon", ico)))
    }

    @Test
    fun icoPicksPngEntryOverBmpEntry() {
        val bmp = byteArrayOf(0x42, 0x4D, 9, 9, 9, 9)
        val ico = ico(listOf(bmp.size to bmp, pngBytes.size to pngBytes))
        assertContentEquals(pngBytes, SiteIcon.fromCipherJson(faviconJson("image/x-icon", ico)))
    }

    @Test
    fun icoWithoutPngEntryStaysRaw() {
        // BMP-style entry: no PNG signature anywhere; the raw container is
        // returned and each platform decoder decides.
        val bmp = byteArrayOf(0x42, 0x4D, 1, 2, 3, 4)
        val ico = ico(listOf(bmp.size to bmp))
        assertContentEquals(ico, SiteIcon.fromCipherJson(faviconJson("image/x-icon", ico)))
    }

    @Test
    fun truncatedIcoDirectoryIsSafe() {
        val ico = byteArrayOf(0, 0, 1, 0, 9, 0, 1, 2, 3, 4)
        assertContentEquals(ico, SiteIcon.fromCipherJson(faviconJson("image/x-icon", ico)))
    }

    @Test
    fun rejectsNonAllowlistedMime() {
        assertNull(SiteIcon.fromCipherJson(faviconJson("image/svg+xml", pngBytes)))
        assertNull(SiteIcon.fromCipherJson(faviconJson("text/html", pngBytes)))
    }

    @Test
    fun rejectsMalformedPayloads() {
        assertNull(SiteIcon.fromCipherJson("not json"))
        assertNull(SiteIcon.fromCipherJson("""{"name":"x"}"""))
        assertNull(
            SiteIcon.fromCipherJson(
                """{"favicon":{"data":"!!!not-base64!!!","mime":"image/png"}}""",
            ),
        )
        assertNull(
            SiteIcon.fromCipherJson(
                """{"favicon":{"data":"${Base64.encode(byteArrayOf(1, 2))}","mime":"image/png"}}""",
            ),
        )
    }

    @Test
    fun faviconFieldAbsenceIsNotAnError() {
        assertEquals(null, SiteIcon.fromCipherJson("""{"name":"x","kind":{"type":"card","data":{}}}"""))
    }
}
