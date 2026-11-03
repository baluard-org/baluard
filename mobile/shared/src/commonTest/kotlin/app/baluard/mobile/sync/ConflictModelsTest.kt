package app.baluard.mobile.sync

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** B4: the wire JSON of `getPendingConflictDetails` parses into the DTO. */
class ConflictModelsTest {

    @Test
    fun parsesNothingPending() {
        val dto = parsePendingConflict("""{"pending":false}""")!!
        assertFalse(dto.pending)
        assertFalse(dto.autoMerged)
        assertFalse(dto.crossEpoch)
        assertEquals(0, dto.fields.size)
    }

    @Test
    fun parsesAutoMerged() {
        val dto = parsePendingConflict(
            """{"pending":false,"auto_merged":true,"push_pending":true}""",
        )!!
        assertTrue(dto.autoMerged)
        assertTrue(dto.pushPending)
    }

    @Test
    fun parsesCrossEpoch() {
        val dto = parsePendingConflict(
            """{"pending":true,"cross_epoch":true,"unreachable_side":"remote",
                "detail":"epoch mismatch","count":2}""",
        )!!
        assertTrue(dto.pending)
        assertTrue(dto.crossEpoch)
        assertEquals("remote", dto.unreachableSide)
        assertEquals(2, dto.count)
    }

    @Test
    fun parsesRealConflict() {
        val dto = parsePendingConflict(
            """{"pending":true,"cross_epoch":false,"count":1,
                "cipher_id":"6f1d...","name":"GitHub","cipher_type":"login",
                "fields":[{"key":"password","label":"password","sensitive":true},
                          {"key":"notes","label":"notes","sensitive":false}]}""",
        )!!
        assertTrue(dto.pending)
        assertFalse(dto.crossEpoch)
        assertEquals("GitHub", dto.name)
        assertEquals("login", dto.cipherType)
        assertEquals(2, dto.fields.size)
        assertTrue(dto.fields[0].sensitive)
        assertFalse(dto.fields[1].sensitive)
    }

    @Test
    fun toleratesUnknownKeys() {
        val dto = parsePendingConflict(
            """{"pending":true,"cross_epoch":false,"future_field":42,
                "cipher_id":"x","name":"N","cipher_type":"login","fields":[]}""",
        )!!
        assertTrue(dto.pending)
        assertEquals("N", dto.name)
    }

    @Test
    fun malformedBodyYieldsNull() {
        assertNull(parsePendingConflict("not json"))
        assertNull(parsePendingConflict("""{"pending":""}"""))
    }

    @Test
    fun verdictWireStringsMatchRuntime() {
        assertEquals("keep_local", ConflictVerdict.KEEP_LOCAL.wire)
        assertEquals("keep_remote", ConflictVerdict.KEEP_REMOTE.wire)
        assertEquals("keep_both", ConflictVerdict.KEEP_BOTH.wire)
    }
}
