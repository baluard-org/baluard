package xyz.actitud.baluard.vault

import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Deep-search haystack: every content field indexed, password never. */
class SearchHaystackTest {
    // Tripwire: a refactor that drops one of these from SEARCH_SKIP_KEYS
    // fails this test instead of leaking a seed or key into the search index.
    private val neverIndexable = setOf(
        "password", "password_history", "private_key", "prf_key", "totp_uri",
        "code", "pin", "ssn",
    )


    @Test
    fun indexesAllContentFieldsExceptPassword() {
        val raw = """
            {"id":"abc-123","cipher_type":"login","name":"GitHub",
             "username":"me@example.com","favorite":false,
             "kind":{"type":"login","data":{
               "username":"me@example.com","password":"s3cret!",
               "uris":[{"uri":"https://github.com/login"}],
               "notes":"work account",
               "custom_fields":[
                 {"name":"employee id","value":"4471","field_type":"text"},
                 {"name":"api key","value":"sk-99","field_type":"hidden"}]}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertTrue(h.contains("github.com"), "URIs")
        assertTrue(h.contains("work account"), "notes")
        assertTrue(h.contains("4471"), "text custom field")
        assertTrue(h.contains("sk-99"), "hidden custom field: search everything")
        assertFalse(h.contains("s3cret"), "password never")
    }

    @Test
    fun indexesNonLoginCipherTypes() {
        val raw = """
            {"name":"Visa","kind":{"type":"card","data":{
               "number":"4111111111111111","cardholder_name":"E","exp_month":12}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertTrue(h.contains("4111111111111111"), "card number")
        assertTrue(h.contains("12"), "numeric field")
    }

    @Test
    fun wireNoiseNeverEnters() {
        val raw = """
            {"id":"x","cipher_type":"login","key_epoch":3,"favorite":true,
             "kind":{"type":"login","data":{}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertFalse(h.contains("login"), "type tag would match every entry")
        assertTrue(h.isEmpty())
    }

    @Test
    fun oldPasswordsStayOut() {
        val raw = """
            {"kind":{"type":"login","data":{"password_history":[
               {"password":"old-pass!","last_used_date":1700000000}]}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertFalse(h.contains("old-pass!"))
        assertFalse(h.contains("1700000000"), "password_history subtree pruned, not just values")
    }

    @Test
    fun faviconBase64StaysOut() {
        val raw = """
            {"name":"GitHub","kind":{"type":"login","data":{
               "favicon":{"data":"iVBORw0KGgoAAAANSUhEUg==","mime":"image/png"}}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertFalse(h.contains("ivbor"), "base64 blob")
        assertFalse(h.contains("image/png"), "mime noise")
    }

    @Test
    fun envelopeNoiseStaysOut() {
        val raw = """
            {"id":"x","name":"Git","tier":"s","update_seq":42,"key_epoch":7,
             "kind":{"type":"login","data":{}}}
        """.trimIndent()
        assertEquals("git", buildSearchHaystack(raw))
    }

    @Test
    fun passkeyBlobsAndDiscriminatorsStayOut() {
        val raw = """
            {"name":"GitHub passkey","kind":{"type":"login","data":{
               "fido2_credentials":[{
                 "credential_id":"cHJvb2ZAbWF4aW11bS12YWxpZC1sZW5ndGg","key_type":"public-key",
                 "key_algorithm":"ECDSA","key_curve":"P-256",
                 "key_value":"pQECAyYgASFYILONGtNdbCOkkYIGە","rp_id":"github.com",
                 "rp_name":"GitHub","user_handle":[104,101,108,108,111],
                 "user_name":"alex@example.com","counter":5,
                 "creation_date":1700000000,"private_key_missing":false}]}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertTrue(h.contains("github.com"), "rp id is content")
        assertTrue(h.contains("alex@example.com"), "user name is content")
        assertFalse(h.contains("pqec"), "COSE public key blob")
        assertFalse(h.contains("public-key"), "key type discriminator")
        assertFalse(h.contains("ecdsa"), "algorithm discriminator")
        assertFalse(h.contains("p-256"), "curve discriminator")
        assertFalse(h.contains("1700000000"), "creation timestamp")
        assertFalse(h.contains("104"), "user_handle byte array")
    }

    @Test
    fun sshKeyMaterialStaysOut() {
        val raw = """
            {"name":"deploy key","kind":{"type":"sshKey","data":{
               "public_key":"ssh-ed25519 AAAAC3","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----",
               "key_fingerprint":"SHA256:abc"}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertTrue(h.contains("sha256:abc"), "fingerprint")
        assertFalse(h.contains("begin openssh"), "private key")
    }

    @Test
    fun totpSeedStaysOut() {
        val raw = """
            {"name":"GitHub","kind":{"type":"login","data":{
               "totp_uri":"otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertFalse(h.contains("jbswy3dpeh"), "live seed")
        assertFalse(h.contains("otpauth"), "uri itself")
    }

    @Test
    fun customFieldTypeDiscriminatorStaysOut() {
        val raw = """
            {"kind":{"type":"login","data":{"custom_fields":[
               {"name":"recovery","value":"backup@mail","field_type":"hidden"}]}}}
        """.trimIndent()
        val h = buildSearchHaystack(raw)
        assertTrue(h.contains("backup@mail"), "field value stays searchable")
        assertFalse(h.contains("hidden"), "type discriminator would match every hidden field")
    }

    @Test
    fun secretKeysAreTripwired() {
        neverIndexable.forEach { key ->
            assertTrue(key in SEARCH_SKIP_KEYS, "$key must never enter the index")
        }
    }

    @Test
    fun garbageYieldsEmptyHaystack() {
        assertEquals("", buildSearchHaystack("not json"))
    }
}
