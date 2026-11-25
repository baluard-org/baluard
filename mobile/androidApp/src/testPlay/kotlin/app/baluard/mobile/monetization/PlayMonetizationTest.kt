package app.baluard.mobile.monetization

import com.android.billingclient.api.Purchase
import org.junit.Assert.assertEquals
import org.junit.Test

private fun purchase(
    state: Int,
    autoRenewing: Boolean = true,
    productId: String = SUBSCRIPTION_PRODUCT_ID,
): Purchase {
    // Billing's wire JSON uses 4 for pending; its getter maps that to PENDING (2).
    val wireState = if (state == Purchase.PurchaseState.PENDING) 4 else 1
    return Purchase(
        """
        {
          "orderId":"GPA.0000-0000-0000-00000",
          "packageName":"app.baluard.mobile",
          "productIds":["$productId"],
          "purchaseTime":1800000000000,
          "purchaseState":$wireState,
          "purchaseToken":"synthetic-purchase-token",
          "quantity":1,
          "acknowledged":true,
          "autoRenewing":$autoRenewing
        }
        """.trimIndent(),
        "",
    )
}

class PlayMonetizationTest {

    @Test
    fun `purchased subscription maps to purchased with renewal flag`() {
        assertEquals(
            StoreQuery.Purchased(willRenew = true),
            mapPurchases(listOf(purchase(Purchase.PurchaseState.PURCHASED, autoRenewing = true))),
        )
        assertEquals(
            StoreQuery.Purchased(willRenew = false),
            mapPurchases(listOf(purchase(Purchase.PurchaseState.PURCHASED, autoRenewing = false))),
        )
    }

    @Test
    fun `pending or unrelated purchases map to nothing active`() {
        assertEquals(
            StoreQuery.NothingActive,
            mapPurchases(listOf(purchase(Purchase.PurchaseState.PENDING))),
        )
        assertEquals(
            StoreQuery.NothingActive,
            mapPurchases(listOf(purchase(Purchase.PurchaseState.PURCHASED, productId = "other_product"))),
        )
        assertEquals(StoreQuery.NothingActive, mapPurchases(emptyList()))
    }
}
