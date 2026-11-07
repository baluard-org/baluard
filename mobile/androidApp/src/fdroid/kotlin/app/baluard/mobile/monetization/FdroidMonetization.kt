package app.baluard.mobile.monetization

import app.baluard.mobile.BaluardApplication

/**
 * F-Droid build: no billing code ships in this package, so everything is free
 * forever (ADR 0102). The purchased-always store makes every gate open.
 */
class FdroidMonetizationApplication : BaluardApplication() {
    override fun onCreate() {
        super.onCreate()
        Entitlements.initialize(store = FreeStore, cache = androidEntitlementCache())
    }
}

internal object FreeStore : MonetizationStore {
    override suspend fun query() = StoreQuery.Purchased(willRenew = true)
    override suspend fun launchPurchase() = false
}
