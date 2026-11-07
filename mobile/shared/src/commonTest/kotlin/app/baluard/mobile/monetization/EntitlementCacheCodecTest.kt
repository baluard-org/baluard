package app.baluard.mobile.monetization

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class EntitlementCacheCodecTest {

    @Test
    fun roundtrips_every_phase() {
        val samples = listOf(
            CachedEntitlement(EntitlementPhase.Locked),
            CachedEntitlement(EntitlementPhase.Unlocked, willRenew = true),
            CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = 1_794_000_000_000L, willRenew = false),
        )
        for (sample in samples) {
            assertEquals(sample, EntitlementCacheCodec.decode(EntitlementCacheCodec.encode(sample)))
        }
    }

    @Test
    fun encodes_null_trial_end_as_dash() {
        assertEquals("Locked;-;false", EntitlementCacheCodec.encode(CachedEntitlement(EntitlementPhase.Locked)))
    }

    @Test
    fun rejects_unknown_phase() {
        assertNull(EntitlementCacheCodec.decode("Unknown;123;true"))
    }

    @Test
    fun rejects_missing_fields() {
        assertNull(EntitlementCacheCodec.decode("Unlocked;"))
        assertNull(EntitlementCacheCodec.decode("Unlocked"))
        assertNull(EntitlementCacheCodec.decode(""))
    }

    @Test
    fun rejects_non_numeric_trial_end() {
        assertNull(EntitlementCacheCodec.decode("Locked;abc;true"))
    }

    @Test
    fun decodes_the_dash_sentinel() {
        val decoded = EntitlementCacheCodec.decode("Locked;-;true")
        assertEquals(CachedEntitlement(EntitlementPhase.Locked, willRenew = true), decoded)
    }
}
