package app.baluard.mobile.monetization

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val DAY_MS = 24L * 60 * 60 * 1000

private const val NOW = 1_794_000_000_000L

class EntitlementTest {

    // ── applyStoreQuery: a completed query always replaces the cache ──

    @Test
    fun queryWithNothingOnNoCacheLocks() {
        val next = applyStoreQuery(null, StoreQuery.NothingActive)
        assertEquals(EntitlementPhase.Locked, next?.phase)
        assertNull(next?.trialEndsAtEpochMs)
    }

    @Test
    fun purchasedQueryUnlocksFromNoCache() {
        val next = applyStoreQuery(null, StoreQuery.Purchased(willRenew = true))
        assertEquals(EntitlementPhase.Unlocked, next?.phase)
        assertTrue(next?.willRenew == true)
    }

    @Test
    fun trialQueryRecordsTheWindow() {
        val next = applyStoreQuery(null, StoreQuery.TrialActive(endsAtEpochMs = NOW + 14 * DAY_MS, willRenew = false))
        assertEquals(EntitlementPhase.Trial, next?.phase)
        assertEquals(NOW + 14 * DAY_MS, next?.trialEndsAtEpochMs)
        assertFalse(next?.willRenew == true)
    }

    @Test
    fun trialUpgradingToPurchasedUnlocks() {
        val trial = CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = NOW + DAY_MS)
        val next = applyStoreQuery(trial, StoreQuery.Purchased(willRenew = true))
        assertEquals(EntitlementPhase.Unlocked, next?.phase)
        assertNull(next?.trialEndsAtEpochMs)
    }

    // ── applyStoreQuery: Unavailable never mutates the cache ──

    @Test
    fun unavailableOnNoCacheStaysUnknown() {
        assertNull(applyStoreQuery(null, StoreQuery.Unavailable))
    }

    @Test
    fun unavailablePreservesAnUnlockedCache() {
        val paid = CachedEntitlement(EntitlementPhase.Unlocked, willRenew = true)
        assertEquals(paid, applyStoreQuery(paid, StoreQuery.Unavailable))
    }

    @Test
    fun unavailablePreservesATrialCache() {
        val trial = CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = NOW + DAY_MS)
        assertEquals(trial, applyStoreQuery(trial, StoreQuery.Unavailable))
    }

    // ── applyStoreQuery: revocation downgrades ──

    @Test
    fun revocationLocksAPaidCache() {
        val paid = CachedEntitlement(EntitlementPhase.Unlocked)
        assertEquals(EntitlementPhase.Locked, applyStoreQuery(paid, StoreQuery.NothingActive)?.phase)
    }

    @Test
    fun expiredTrialQueryReportsLocked() {
        val trial = CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = NOW - DAY_MS)
        assertEquals(EntitlementPhase.Locked, applyStoreQuery(trial, StoreQuery.NothingActive)?.phase)
    }

    @Test
    fun unavailablePreservesAnExplicitLockedCache() {
        val locked = CachedEntitlement(EntitlementPhase.Locked)
        assertEquals(locked, applyStoreQuery(locked, StoreQuery.Unavailable))
    }

    @Test
    fun trialWithNullEndFailsClosed() {
        val eff = effectiveEntitlement(
            CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = null),
            NOW,
        )
        assertEquals(EntitlementPhase.Locked, eff.phase)
        assertFalse(eff.totpUnlocked)
    }

    // ── effectiveEntitlement ──

    @Test
    fun unknownCacheLocksEveryGate() {
        val eff = effectiveEntitlement(null, NOW)
        assertEquals(EntitlementPhase.Unknown, eff.phase)
        assertFalse(eff.syncUnlocked)
        assertFalse(eff.sharingUnlocked)
        assertFalse(eff.totpUnlocked)
        assertNull(eff.trialDaysLeft)
    }

    @Test
    fun purchasedCacheUnlocksEveryGate() {
        val eff = effectiveEntitlement(CachedEntitlement(EntitlementPhase.Unlocked), NOW)
        assertEquals(EntitlementPhase.Unlocked, eff.phase)
        assertTrue(eff.syncUnlocked)
        assertTrue(eff.sharingUnlocked)
        assertTrue(eff.totpUnlocked)
        assertNull(eff.trialDaysLeft)
    }

    @Test
    fun activeTrialUnlocksAndCountsDays() {
        val eff = effectiveEntitlement(
            CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = NOW + 10 * DAY_MS),
            NOW,
        )
        assertEquals(EntitlementPhase.Trial, eff.phase)
        assertTrue(eff.syncUnlocked)
        assertTrue(eff.sharingUnlocked)
        assertTrue(eff.totpUnlocked)
        assertEquals(10, eff.trialDaysLeft)
    }

    @Test
    fun partialTrialDayRoundsUp() {
        val eff = effectiveEntitlement(
            CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = NOW + DAY_MS + 3_600_000L),
            NOW,
        )
        assertEquals(2, eff.trialDaysLeft)
    }

    @Test
    fun expiredTrialLocksGatesUntilTheNextQuery() {
        val eff = effectiveEntitlement(
            CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = NOW - 1),
            NOW,
        )
        assertEquals(EntitlementPhase.Locked, eff.phase)
        assertFalse(eff.syncUnlocked)
        assertFalse(eff.sharingUnlocked)
        assertFalse(eff.totpUnlocked)
    }

    @Test
    fun trialBoundaryAtExpiryLocks() {
        val eff = effectiveEntitlement(
            CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = NOW),
            NOW,
        )
        assertEquals(EntitlementPhase.Locked, eff.phase)
        assertFalse(eff.totpUnlocked)
    }
}
