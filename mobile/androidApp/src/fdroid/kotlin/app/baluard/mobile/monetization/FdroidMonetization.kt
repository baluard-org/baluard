package app.baluard.mobile.monetization

import app.baluard.mobile.BaluardApplication

/**
 * F-Droid build: no billing code ships in this package, so everything is free
 * forever (ADR 0102). The purchased-always store makes every gate open.
 */
class FdroidMonetizationApplication : BaluardApplication() {
    override fun onCreate() {
        super.onCreate()
        Entitlements.initialize(
            store = FreeStore,
            // In-memory and permanently Unlocked: no billing code ships in this
            // package, so no store query is needed, nothing persists, and no
            // fresh-install or cold-process window can ever gate a user (ADR 0102).
            cache = MemoryEntitlementCache().apply { save(CachedEntitlement(EntitlementPhase.Unlocked)) },
        )
    }
}

internal object FreeStore : MonetizationStore {
    override suspend fun query() = StoreQuery.Purchased(willRenew = true)
    override suspend fun purchase() = PurchaseOutcome.Unavailable
}
