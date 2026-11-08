package app.baluard.mobile.monetization

import com.android.billingclient.api.Purchase
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

private class VerificationApi : AutoCloseable {
    private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
    var requestBody: String? = null
    var requestCount = 0
    var responseCode = 200
    var responseBody = """{"active":true,"willRenew":true}"""
    var redirectLocation: String? = null
    var redirectedRequestCount = 0

    val url: String get() = "http://127.0.0.1:${server.address.port}"

    init {
        server.createContext("/v1/entitlements/verify") { exchange ->
            requestCount++
            requestBody = exchange.requestBody.bufferedReader().use { it.readText() }
            val bytes = responseBody.toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            redirectLocation?.let { exchange.responseHeaders.add("Location", it) }
            exchange.sendResponseHeaders(responseCode, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.createContext("/redirect-target") { exchange ->
            redirectedRequestCount++
            val bytes = responseBody.toByteArray()
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
    }

    override fun close() = server.stop(0)
}

private fun purchase(state: Int, token: String = "synthetic-purchase-token"): Purchase {
    // Billing's wire JSON uses 4 for pending; its getter maps that to PENDING (2).
    val wireState = if (state == Purchase.PurchaseState.PENDING) 4 else 1
    return Purchase(
        """
        {
          "orderId":"GPA.0000-0000-0000-00000",
          "packageName":"app.baluard.mobile",
          "productIds":["baluard_supporter_yearly"],
          "purchaseTime":1800000000000,
          "purchaseState":$wireState,
          "purchaseToken":"$token",
          "quantity":1,
          "acknowledged":true,
          "autoRenewing":true
        }
        """.trimIndent(),
        "",
    )
}

class ServerEntitlementVerifierTest {

    @Test
    fun active_response_sends_the_token_and_preserves_cancellation_state() = runTest {
        VerificationApi().use { api ->
            api.responseBody = """{"active":true,"willRenew":false}"""
            val result = ServerEntitlementVerifier(api.url).verify("synthetic-purchase-token")
            assertEquals(StoreQuery.Purchased(willRenew = false), result)
            assertEquals("""{"purchaseToken":"synthetic-purchase-token"}""", api.requestBody)
        }
    }

    @Test
    fun inactive_response_locks_the_entitlement() = runTest {
        VerificationApi().use { api ->
            api.responseBody = """{"active":false}"""
            assertEquals(StoreQuery.NothingActive, ServerEntitlementVerifier(api.url).verify("token"))
        }
    }

    @Test
    fun transient_http_failures_are_unavailable_not_inactive() = runTest {
        for (code in listOf(400, 429, 500, 503)) {
            VerificationApi().use { api ->
                api.responseCode = code
                api.responseBody = """{"error":"verification_unavailable"}"""
                assertEquals(StoreQuery.Unavailable, ServerEntitlementVerifier(api.url).verify("token"))
            }
        }
    }

    @Test
    fun malformed_active_response_is_unavailable() = runTest {
        VerificationApi().use { api ->
            api.responseBody = """{"active":true}"""
            assertEquals(StoreQuery.Unavailable, ServerEntitlementVerifier(api.url).verify("token"))
        }
    }

    @Test
    fun invalid_endpoint_configuration_is_unavailable_without_crashing() = runTest {
        val invalidUrls = listOf(
            "http://entitlements.example.com",
            "not a URL",
            "https://user@entitlements.example.com",
        )
        for (url in invalidUrls) {
            assertEquals(StoreQuery.Unavailable, ServerEntitlementVerifier(url).verify("token"))
        }
    }

    @Test
    fun redirects_are_not_followed() = runTest {
        VerificationApi().use { api ->
            api.responseCode = 302
            api.redirectLocation = "${api.url}/redirect-target"
            assertEquals(StoreQuery.Unavailable, ServerEntitlementVerifier(api.url).verify("token"))
            assertEquals(0, api.redirectedRequestCount)
        }
    }

    @Test
    fun local_billing_mapping_still_works_without_a_service_url() = runTest {
        val result = mapPurchases(listOf(purchase(Purchase.PurchaseState.PURCHASED)), verifier = null)
        assertEquals(StoreQuery.Purchased(willRenew = true), result)
    }

    @Test
    fun server_response_replaces_the_local_purchase_assertion() = runTest {
        VerificationApi().use { api ->
            api.responseBody = """{"active":false}"""
            val result = mapPurchases(
                listOf(purchase(Purchase.PurchaseState.PURCHASED)),
                ServerEntitlementVerifier(api.url),
            )
            assertEquals(StoreQuery.NothingActive, result)
        }
    }

    @Test
    fun server_outage_preserves_the_cached_entitlement() = runTest {
        VerificationApi().use { api ->
            api.responseCode = 503
            val result = mapPurchases(
                listOf(purchase(Purchase.PurchaseState.PURCHASED)),
                ServerEntitlementVerifier(api.url),
            )
            assertEquals(StoreQuery.Unavailable, result)
        }
    }

    @Test
    fun pending_purchase_does_not_reach_the_verification_service() = runTest {
        VerificationApi().use { api ->
            val result = mapPurchases(
                listOf(purchase(Purchase.PurchaseState.PENDING)),
                ServerEntitlementVerifier(api.url),
            )
            assertEquals(StoreQuery.NothingActive, result)
            assertEquals(0, api.requestCount)
        }
    }
}
