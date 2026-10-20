package xyz.actitud.baluard.passkeys

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class OriginRulesTest {

    private val allowlist = """
        {"apps":[
            {"info":{"package_name":"com.android.chrome"},
             "signatures":[{"cert_fingerprint_sha256":"AA:BB"}]},
            {"info":{"package_name":"org.mozilla.firefox"},
             "signatures":[{"cert_fingerprint_sha256":"CC:DD"}]}
        ]}
    """.trimIndent()

    @Test
    fun allowlistPackages_parsesGoogleFormat() {
        assertEquals(setOf("com.android.chrome", "org.mozilla.firefox"), OriginRules.allowlistPackages(allowlist))
    }

    @Test
    fun allowlistPackages_malformedFailsClosedToEmpty() {
        assertEquals(emptySet(), OriginRules.allowlistPackages("not json"))
        assertEquals(emptySet(), OriginRules.allowlistPackages("{\"other\":1}"))
    }

    private val dal = """
        [{"relation":["delegate_permission/common.handle_all_urls"],
          "target":{"namespace":"web","site":"https://example.com"}},
         {"relation":["delegate_permission/common.get_login_creds"],
          "target":{"namespace":"android_app","package_name":"com.app.test",
                    "sha256_cert_fingerprints":["AA:BB:CC"]}}]
    """.trimIndent()

    @Test
    fun assetLinksGrant_matchesRelationPackageAndFingerprint() {
        assertTrue(OriginRules.assetLinksGrant(dal, "com.app.test", "AA:BB:CC"))
        assertTrue(OriginRules.assetLinksGrant(dal, "com.app.test", "aabbcc"))
        assertFalse(OriginRules.assetLinksGrant(dal, "com.other", "AA:BB:CC"))
        assertFalse(OriginRules.assetLinksGrant(dal, "com.app.test", "FF:EE"))
    }

    @Test
    fun assetLinksGrant_handleAllUrlsAloneDoesNotGrant() {
        val onlyAppLinks = """
            [{"relation":["delegate_permission/common.handle_all_urls"],
              "target":{"namespace":"android_app","package_name":"com.app.test",
                        "sha256_cert_fingerprints":["AA:BB:CC"]}}]
        """.trimIndent()
        assertFalse(OriginRules.assetLinksGrant(onlyAppLinks, "com.app.test", "AA:BB:CC"))
    }

    @Test
    fun assetLinksGrant_malformedFailsClosed() {
        assertFalse(OriginRules.assetLinksGrant("nope", "com.app.test", "AA"))
    }

    @Test
    fun fetchableHost_rules() {
        // Public names always fetchable.
        assertTrue(OriginRules.isFetchableHost("example.com", allowLocal = false))
        assertTrue(OriginRules.isFetchableHost("rp.example.co.uk.", allowLocal = false))
        // Local names and IP literals refused outside debug.
        assertFalse(OriginRules.isFetchableHost("localhost", allowLocal = false))
        assertFalse(OriginRules.isFetchableHost("127.0.0.1", allowLocal = false))
        assertFalse(OriginRules.isFetchableHost("10.0.0.4", allowLocal = true))
        assertFalse(OriginRules.isFetchableHost("192.168.1.2", allowLocal = true))
        assertFalse(OriginRules.isFetchableHost("::1", allowLocal = false))
        assertFalse(OriginRules.isFetchableHost("box.local", allowLocal = false))
        // Debug affordance: loopback only, never other private ranges.
        assertTrue(OriginRules.isFetchableHost("localhost", allowLocal = true))
        assertTrue(OriginRules.isFetchableHost("127.0.0.1", allowLocal = true))
    }

    @Test
    fun rpIdCoversOriginHost_webauthnContainment() {
        assertTrue(OriginRules.rpIdCoversOriginHost("example.com", "example.com"))
        assertTrue(OriginRules.rpIdCoversOriginHost("example.com", "www.example.com"))
        assertFalse(OriginRules.rpIdCoversOriginHost("example.com", "badexample.com"))
        assertFalse(OriginRules.rpIdCoversOriginHost("example.com", "example.org"))
        assertFalse(OriginRules.rpIdCoversOriginHost("", "example.com"))
    }

    @Test
    fun isLocalRpHost_matchesTheFetchGuard() {
        assertTrue(OriginRules.isLocalRpHost("localhost", allowLocal = true))
        assertTrue(OriginRules.isLocalRpHost("e2e.localhost", allowLocal = true))
        assertTrue(OriginRules.isLocalRpHost("127.0.0.1", allowLocal = true))
        assertFalse(OriginRules.isLocalRpHost("localhost", allowLocal = false))
        assertFalse(OriginRules.isLocalRpHost("example.com", allowLocal = true))
        assertFalse(OriginRules.isLocalRpHost("attacker.local", allowLocal = true))
    }
}
