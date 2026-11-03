package app.baluard.mobile.platform

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SecurityKeyHidTest {
    @Test
    fun recognizesTheFidoHidUsagePage() {
        assertTrue(hidReportHasFidoUsagePage(byteArrayOf(0x06, 0xD0.toByte(), 0xF1.toByte())))
    }

    @Test
    fun skipsOtherItemsAndLongItems() {
        val report = byteArrayOf(
            0x06, 0x00, 0xFF.toByte(),
            0x09, 0x01,
            0xFE.toByte(), 0x02, 0x00, 0x55, 0x55,
            0x06, 0xD0.toByte(), 0xF1.toByte(),
        )
        assertTrue(hidReportHasFidoUsagePage(report))
    }

    @Test
    fun refusesOtherUsagePagesAndTruncatedDescriptors() {
        assertFalse(hidReportHasFidoUsagePage(byteArrayOf(0x05, 0x01)))
        assertFalse(hidReportHasFidoUsagePage(byteArrayOf(0x06, 0xD0.toByte())))
        assertFalse(hidReportHasFidoUsagePage(byteArrayOf(0xFE.toByte(), 0x04, 0x00, 0x01)))
    }
}
