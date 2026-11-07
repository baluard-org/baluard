package app.baluard.mobile.monetization

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private const val DAY_MS = 24L * 60 * 60 * 1000
private const val NOW = 1_794_000_000_000L

/** Scripted store: each query returns [next]; can throw to simulate billing crashes. */
private class FakeStore(
    var next: StoreQuery,
    var purchaseOutcome: PurchaseOutcome = PurchaseOutcome.Unavailable,
    var throwOnQuery: Boolean = false,
    override val isPaidStore: Boolean = false,
) : MonetizationStore {
    var queryCalls = 0
    override suspend fun query(): StoreQuery {
        queryCalls++
        if (throwOnQuery) throw RuntimeException("billing down")
        return next
    }

    override suspend fun purchase() = purchaseOutcome
}

/** Cache spy counting saves, so tests can assert write suppression. */
private class CountingCache(initial: CachedEntitlement?) : EntitlementCache {
    var saves = 0
    private var value: CachedEntitlement? = initial
    override fun load(): CachedEntitlement? = value
    override fun save(value: CachedEntitlement?) {
        saves++
        this.value = value
    }
}

class EntitlementGateTest {

    @Test
    fun supporter_status_requires_an_active_purchase_from_a_paid_store() = runTest {
        val gate = EntitlementGate { NOW }
        gate.initialize(
            FakeStore(StoreQuery.Purchased(willRenew = true), isPaidStore = true),
            MemoryEntitlementCache(),
        )
        assertFalse(gate.shouldShowSupporterStatus(gate.current()))
        gate.refresh()
        assertTrue(gate.shouldShowSupporterStatus(gate.current()))
    }

    @Test
    fun supporter_status_stays_hidden_for_a_free_unlocked_store() = runTest {
        val gate = EntitlementGate { NOW }
        gate.initialize(FakeStore(StoreQuery.Purchased(willRenew = true)), MemoryEntitlementCache())
        gate.refresh()
        assertTrue(gate.current().syncUnlocked)
        assertFalse(gate.shouldShowSupporterStatus(gate.current()))
    }

    @Test
    fun initialize_seeds_state_from_persisted_cache() {
        val gate = EntitlementGate { NOW }
        val cache = MemoryEntitlementCache().apply { save(CachedEntitlement(EntitlementPhase.Unlocked)) }
        gate.initialize(FakeStore(StoreQuery.Unavailable), cache)
        assertTrue(gate.state.value.syncUnlocked)
        assertEquals(EntitlementPhase.Unlocked, gate.current().phase)
    }

    @Test
    fun current_reflects_persisted_cache_without_refresh() {
        val gate = EntitlementGate { NOW }
        gate.initialize(FakeStore(StoreQuery.Unavailable), MemoryEntitlementCache())
        // The store was never queried; the Unknown snapshot locks, but the
        // persisted cache a real app would already hold would flow through
        // current() with no refresh call.
        assertEquals(EntitlementPhase.Unknown, gate.current().phase)
        assertFalse(gate.current().totpUnlocked)
    }

    @Test
    fun refresh_unavailable_preserves_an_explicit_locked_cache() = runTest {
        var now = NOW
        val gate = EntitlementGate { now }
        val cache = CountingCache(CachedEntitlement(EntitlementPhase.Locked))
        gate.initialize(FakeStore(StoreQuery.Unavailable), cache)
        val eff = gate.refresh()
        assertEquals(EntitlementPhase.Locked, eff.phase)
        assertFalse(eff.syncUnlocked)
        assertEquals(0, cache.saves) // Unavailable suppressed the rewrite
        assertFalse(gate.current().totpUnlocked)
    }

    @Test
    fun refresh_purchased_persists_and_publishes() = runTest {
        val gate = EntitlementGate { NOW }
        val cache = MemoryEntitlementCache()
        gate.initialize(FakeStore(StoreQuery.Purchased(willRenew = true)), cache)
        val eff = gate.refresh()
        assertEquals(EntitlementPhase.Unlocked, eff.phase)
        assertTrue(eff.syncUnlocked)
        assertEquals(EntitlementPhase.Unlocked, cache.load()?.phase)
    }

    @Test
    fun refresh_does_not_rewrite_an_unchanged_cache() = runTest {
        val gate = EntitlementGate { NOW }
        val cache = CountingCache(CachedEntitlement(EntitlementPhase.Unlocked, willRenew = true))
        gate.initialize(FakeStore(StoreQuery.Purchased(willRenew = true)), cache)
        gate.refresh()
        assertEquals(0, cache.saves) // identical next value: never written
    }

    @Test
    fun throwing_store_maps_to_unavailable() = runTest {
        val gate = EntitlementGate { NOW }
        val cache = MemoryEntitlementCache().apply { save(CachedEntitlement(EntitlementPhase.Unlocked)) }
        gate.initialize(FakeStore(StoreQuery.Unavailable, throwOnQuery = true), cache)
        val eff = gate.refresh()
        assertEquals(EntitlementPhase.Unlocked, eff.phase)
        assertEquals(EntitlementPhase.Unlocked, cache.load()?.phase)
    }

    @Test
    fun expired_trial_locks_between_refreshes() {
        var now = NOW
        val gate = EntitlementGate { now }
        val cache = MemoryEntitlementCache().apply {
            save(CachedEntitlement(EntitlementPhase.Trial, trialEndsAtEpochMs = NOW + DAY_MS))
        }
        gate.initialize(FakeStore(StoreQuery.Unavailable), cache)
        assertTrue(gate.current().totpUnlocked)
        now += DAY_MS + 1
        assertFalse(gate.current().totpUnlocked)
        assertEquals(EntitlementPhase.Locked, gate.current().phase)
    }

    @Test
    fun purchase_refreshes_the_cache() = runTest {
        val gate = EntitlementGate { NOW }
        val cache = MemoryEntitlementCache()
        gate.initialize(
            FakeStore(StoreQuery.Purchased(willRenew = true), purchaseOutcome = PurchaseOutcome.Purchased),
            cache,
        )
        assertEquals(PurchaseOutcome.Purchased, gate.purchase())
        assertEquals(EntitlementPhase.Unlocked, gate.current().phase)
    }

    @Test
    fun purchase_cancellation_does_not_refresh() = runTest {
        val gate = EntitlementGate { NOW }
        val cache = MemoryEntitlementCache().apply { save(CachedEntitlement(EntitlementPhase.Locked)) }
        gate.initialize(
            FakeStore(StoreQuery.NothingActive, purchaseOutcome = PurchaseOutcome.Cancelled),
            cache,
        )
        assertEquals(PurchaseOutcome.Cancelled, gate.purchase())
        assertEquals(EntitlementPhase.Locked, gate.current().phase)
    }

    @Test
    fun purchase_pending_does_not_refresh() = runTest {
        val gate = EntitlementGate { NOW }
        val cache = CountingCache(CachedEntitlement(EntitlementPhase.Locked))
        gate.initialize(
            FakeStore(StoreQuery.NothingActive, purchaseOutcome = PurchaseOutcome.Pending),
            cache,
        )
        assertEquals(PurchaseOutcome.Pending, gate.purchase())
        // Payment is unsettled: the cache stays exactly as it was.
        assertEquals(EntitlementPhase.Locked, gate.current().phase)
        assertEquals(0, cache.saves)
    }

    @Test
    fun purchase_store_crash_maps_to_error() = runTest {
        val gate = EntitlementGate { NOW }
        gate.initialize(object : MonetizationStore {
            override suspend fun query() = StoreQuery.NothingActive
            override suspend fun purchase(): PurchaseOutcome = throw RuntimeException("sheet died")
        }, MemoryEntitlementCache())
        assertTrue(gate.purchase() is PurchaseOutcome.Error)
    }
}
