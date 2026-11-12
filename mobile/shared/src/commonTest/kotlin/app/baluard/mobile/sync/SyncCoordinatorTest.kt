package app.baluard.mobile.sync

import kotlinx.coroutines.test.runTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import app.baluard.mobile.monetization.CachedEntitlement
import app.baluard.mobile.monetization.EntitlementPhase
import app.baluard.mobile.monetization.Entitlements
import app.baluard.mobile.monetization.MemoryEntitlementCache
import app.baluard.mobile.monetization.MonetizationStore
import app.baluard.mobile.monetization.PurchaseOutcome
import app.baluard.mobile.monetization.StoreQuery

private object UnlockedTestStore : MonetizationStore {
    override suspend fun query() = StoreQuery.Purchased(willRenew = true)
    override suspend fun purchase() = PurchaseOutcome.Unavailable
}

private object LockedTestStore : MonetizationStore {
    override suspend fun query() = StoreQuery.NothingActive
    override suspend fun purchase() = PurchaseOutcome.Unavailable
}

/** B3: config gating maps lifecycle events onto the FFI event surface. */
class SyncCoordinatorTest {

    @BeforeTest
    fun unlockGates() {
        // The coordinator reads the entitlement per event (ADR 0102); the
        // shared Entitlements singleton must carry an unlocked cache for the
        // config-gating tests below to exercise their intended paths.
        Entitlements.initialize(
            UnlockedTestStore,
            MemoryEntitlementCache().apply { save(CachedEntitlement(EntitlementPhase.Unlocked)) },
        )
    }

    @Test
    fun lockedEntitlementSkipsEverySyncEvent() = runTest {
        Entitlements.initialize(
            LockedTestStore,
            MemoryEntitlementCache().apply { save(CachedEntitlement(EntitlementPhase.Locked)) },
        )
        val vault = StubVault()
        val sync = SyncCoordinator(isMeteredNetwork = { false })
        sync.onUnlock(vault)
        assertFalse(sync.onMutation(vault))
        sync.onForeground(vault)
        sync.onBackground(vault)
        sync.pullNow(vault)
        sync.offlineTick(vault)
        assertEquals(emptyList(), vault.calls)
    }

    @Test
    fun defaultsCallEveryEvent() = runTest {
        val vault = StubVault()
        val sync = SyncCoordinator(isMeteredNetwork = { false })
        sync.onUnlock(vault)
        assertTrue(sync.onMutation(vault))
        sync.onForeground(vault)
        sync.onBackground(vault)
        sync.pullNow(vault)
        sync.offlineTick(vault)
        assertEquals(
            listOf(
                "syncOnUnlock", "syncOnMutation", "syncOnForeground",
                "syncOnBackground", "syncPullNow", "syncOfflineTick",
            ),
            vault.calls,
        )
    }

    @Test
    fun disabledGatesSkipTheirEvent() = runTest {
        val vault = StubVault()
        val sync = SyncCoordinator(
            SyncConfig(syncOnUnlock = false, syncAfterChange = false, syncOnForeground = false),
            isMeteredNetwork = { false },
        )
        sync.onUnlock(vault)
        assertFalse(sync.onMutation(vault))
        sync.onForeground(vault)
        // onBackground is NOT gated: flushing the debounce on background is
        // mandatory (the OS drops the 5s timer on suspension).
        sync.onBackground(vault)
        assertEquals(listOf("syncOnBackground"), vault.calls)
    }

    @Test
    fun wifiOnlySkipsAutomaticEventsOnMeteredNetwork() = runTest {
        val vault = StubVault()
        val sync = SyncCoordinator(isMeteredNetwork = { true })
        sync.onUnlock(vault)
        assertFalse(sync.onMutation(vault))
        sync.onForeground(vault)
        sync.offlineTick(vault)
        // Explicit gesture + mandatory flush are NOT gated by Wi-Fi-only.
        sync.pullNow(vault)
        sync.onBackground(vault)
        assertEquals(listOf("syncPullNow", "syncOnBackground"), vault.calls)
    }

    @Test
    fun statusProxiesVault() = runTest {
        val vault = StubVault()
        val status = SyncCoordinator(isMeteredNetwork = { false }).status(vault)
        assertTrue(status.active)
        assertEquals("idle", status.state)
    }
}
