package xyz.actitud.baluard.detail

import kotlin.test.Test
import kotlin.test.assertEquals

class CipherDetailFormatTest {

    @Test
    fun formatEpochDateHandlesKnownDatesAndLeapYears() {
        assertEquals("1970-01-01", formatEpochDate(0L))
        assertEquals("2000-01-01", formatEpochDate(946684800L))
        assertEquals("2000-02-29", formatEpochDate(951782400L))
        assertEquals("2000-03-01", formatEpochDate(951868800L))
        assertEquals("2026-09-12", formatEpochDate(1789171200L))
    }

    @Test
    fun formatBytesFormatsUnitsCorrectly() {
        assertEquals("0 B", formatBytes(0L))
        assertEquals("500 B", formatBytes(500L))
        assertEquals("1.0 KB", formatBytes(1024L))
        assertEquals("1.5 KB", formatBytes(1536L))
        assertEquals("1.0 MB", formatBytes(1_048_576L))
        assertEquals("2.5 MB", formatBytes(2_621_440L))
    }
}
