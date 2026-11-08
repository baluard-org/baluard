package app.baluard.mobile.monetization

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeFalse
import org.junit.Test

class ServerEntitlementContractTest {

    @Test
    fun kotlin_client_reads_the_node_service_contract() = runTest {
        val url = System.getenv("BALUARD_TEST_ENTITLEMENT_URL")
        assumeFalse(url.isNullOrBlank())
        val result = ServerEntitlementVerifier(requireNotNull(url)).verify("synthetic-contract-token")
        assertEquals(StoreQuery.Purchased(willRenew = false), result)
    }
}
