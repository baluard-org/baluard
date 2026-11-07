package app.baluard.mobile.monetization

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import app.baluard.mobile.BaluardApplication
import com.android.billingclient.api.AcknowledgePurchaseParams
import com.android.billingclient.api.BillingClient
import com.android.billingclient.api.BillingClientStateListener
import com.android.billingclient.api.BillingFlowParams
import com.android.billingclient.api.BillingResult
import com.android.billingclient.api.ProductDetails
import com.android.billingclient.api.Purchase
import com.android.billingclient.api.PurchasesUpdatedListener
import com.android.billingclient.api.QueryProductDetailsParams
import com.android.billingclient.api.QueryPurchasesParams
import com.android.billingclient.api.queryProductDetails
import com.android.billingclient.api.queryPurchasesAsync

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Play build: the BillingClient store backs the sync/sharing/TOTP gates
 * (ADR 0102). Initialized before any activity so the first frame already
 * carries the persisted entitlement.
 */
class PlayMonetizationApplication : BaluardApplication() {
    override fun onCreate() {
        super.onCreate()
        val store = PlayBillingStore(this)
        // launchBillingFlow needs an Activity, not the application context:
        // the store tracks the resumed one via lifecycle callbacks.
        registerActivityLifecycleCallbacks(store.lifecycleCallbacks)
        Entitlements.initialize(store = store, cache = androidEntitlementCache())
    }
}

/**
 * Google Play Billing store for [SUBSCRIPTION_PRODUCT_ID]. All client calls run
 * on the main thread (Play requirement) via [withContext]; the suspend surface
 * stays the [MonetizationStore] contract, so the gate never sees billing types.
 *
 * Threading note: BillingClient callbacks arrive on the main looper, and every
 * deferred they complete is read from suspending call sites, so no extra
 * synchronization beyond the deferred handoff is needed.
 */
internal class PlayBillingStore(context: Context) : MonetizationStore {

    val lifecycleCallbacks = object : Application.ActivityLifecycleCallbacks {
        override fun onActivityResumed(activity: Activity) {
            resumedActivity = activity
        }

        override fun onActivityDestroyed(activity: Activity) {
            if (resumedActivity === activity) resumedActivity = null
        }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
        override fun onActivityStarted(activity: Activity) {}
        override fun onActivityPaused(activity: Activity) {}
        override fun onActivityStopped(activity: Activity) {}
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
    }

    @Volatile
    private var resumedActivity: Activity? = null

    private val main = Dispatchers.Main.immediate
    private val client: BillingClient = BillingClient.newBuilder(context)
        .setListener { result, purchases -> onPurchasesUpdated(result, purchases.orEmpty()) }
        .enablePendingPurchases(
            com.android.billingclient.api.PendingPurchasesParams.newBuilder().build(),
        )
        .build()

    private var connected = CompletableDeferred<Boolean>()

    private var purchaseFlow: CompletableDeferred<PurchaseOutcome>? = null

    @Volatile
    private var detailsCache: ProductDetails? = null

    private suspend fun connect(): Boolean {
        if (client.isReady) return true
        if (!connected.isCompleted) {
            connected = CompletableDeferred()
            client.startConnection(object : BillingClientStateListener {
                override fun onBillingSetupFinished(result: BillingResult) {
                    connected.complete(result.responseCode == BillingClient.BillingResponseCode.OK)
                }

                override fun onBillingServiceDisconnected() {
                    // The next call re-runs startConnection; stale deferreds resolve false.
                    if (!connected.isCompleted) connected.complete(false)
                }
            })
        }
        return withTimeoutOrNull(15_000) { connected.await() } ?: false
    }

    /** Suspend form via billing-ktx; failures return null without caching so the next attempt retries. */
    private suspend fun details(): ProductDetails? {
        detailsCache?.let { return it }
        val params = QueryProductDetailsParams.newBuilder()
            .setProductList(
                listOf(
                    QueryProductDetailsParams.Product.newBuilder()
                        .setProductId(SUBSCRIPTION_PRODUCT_ID)
                        .setProductType(BillingClient.ProductType.SUBS)
                        .build(),
                ),
            )
            .build()
        val result = client.queryProductDetails(params)
        if (result.billingResult.responseCode != BillingClient.BillingResponseCode.OK) return null
        return result.productDetailsList?.firstOrNull()?.also { detailsCache = it }
    }

    override suspend fun query(): StoreQuery {
        if (!connect()) return StoreQuery.Unavailable
        val result = client.queryPurchasesAsync(
            QueryPurchasesParams.newBuilder().setProductType(BillingClient.ProductType.SUBS).build(),
        )
        if (result.billingResult.responseCode != BillingClient.BillingResponseCode.OK) return StoreQuery.Unavailable
        return mapPurchases(result.purchasesList)
    }

    override suspend fun purchase(): PurchaseOutcome = withContext(main) {
        if (!connect()) return@withContext PurchaseOutcome.Unavailable
        val activity = resumedActivity ?: return@withContext PurchaseOutcome.Unavailable
        val details = details() ?: return@withContext PurchaseOutcome.Unavailable
        val offer = details.subscriptionOfferDetails?.firstOrNull()
            ?: return@withContext PurchaseOutcome.Unavailable
        val params = BillingFlowParams.newBuilder()
            .setProductDetailsParamsList(
                listOf(
                    BillingFlowParams.ProductDetailsParams.newBuilder()
                        .setProductDetails(details)
                        .setOfferToken(offer.offerToken)
                        .build(),
                ),
            )
            .build()
        val flow = CompletableDeferred<PurchaseOutcome>()
        purchaseFlow = flow
        val code = client.launchBillingFlow(activity, params).responseCode
        if (code != BillingClient.BillingResponseCode.OK && code != BillingClient.BillingResponseCode.USER_CANCELED) {
            purchaseFlow = null
            return@withContext PurchaseOutcome.Error("billing flow failed: $code")
        }
        // The Google sheet can stay open as long as the user likes; beyond
        // 5 minutes the attempt is treated as abandoned. query() restores the
        // truth on the next refresh either way.
        withTimeoutOrNull(5 * 60 * 1000L) { flow.await() } ?: PurchaseOutcome.Cancelled
    }

    private fun onPurchasesUpdated(result: BillingResult, purchases: List<Purchase>) {
        val flow = purchaseFlow ?: return
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> {
                val bought = purchases.filter { it.products.contains(SUBSCRIPTION_PRODUCT_ID) }
                val outcome = if (bought.any { it.purchaseState == Purchase.PurchaseState.PURCHASED }) {
                    // Google requires acknowledgment within 3 days or the
                    // purchase is refunded automatically.
                    bought.filter { !it.isAcknowledged }.forEach { purchase ->
                        client.acknowledgePurchase(
                            AcknowledgePurchaseParams.newBuilder().setPurchaseToken(purchase.purchaseToken).build(),
                        ) { }
                    }
                    PurchaseOutcome.Purchased
                } else {
                    PurchaseOutcome.Cancelled
                }
                purchaseFlow = null
                flow.complete(outcome)
            }
            BillingClient.BillingResponseCode.USER_CANCELED -> {
                purchaseFlow = null
                flow.complete(PurchaseOutcome.Cancelled)
            }
            else -> {
                purchaseFlow = null
                flow.complete(PurchaseOutcome.Error("billing update: ${result.responseCode}"))
            }
        }
    }

    /** Maps a purchases list to the store contract; any active sub unlocks. */
    private fun mapPurchases(purchases: List<Purchase>): StoreQuery {
        val active = purchases.filter { it.products.contains(SUBSCRIPTION_PRODUCT_ID) }
        if (active.none { it.purchaseState == Purchase.PurchaseState.PURCHASED }) return StoreQuery.NothingActive
        return StoreQuery.Purchased(willRenew = active.any { it.isAutoRenewing })
    }
}
