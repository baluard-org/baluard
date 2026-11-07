package app.baluard.mobile.monetization

import android.content.Context
import app.baluard.mobile.BaluardApplication

/**
 * Play build: the BillingClient store backs the sync/sharing/TOTP gates
 * (ADR 0102). Initialized before any activity so the first frame already
 * carries the persisted entitlement.
 */
class PlayMonetizationApplication : BaluardApplication() {
    override fun onCreate() {
        super.onCreate()
        Entitlements.initialize(store = PlayBillingStore(this), cache = androidEntitlementCache())
    }
}

/**
 * Scaffold store: reports Unavailable (cache-preserving, gates locked) until
 * the real BillingClient query and purchase flow land. The billing dependency
 * is already wired so this file grows into the client without build changes.
 */
internal class PlayBillingStore(private val context: Context) : MonetizationStore {
    override suspend fun query() = StoreQuery.Unavailable
    override suspend fun launchPurchase() = false
}
