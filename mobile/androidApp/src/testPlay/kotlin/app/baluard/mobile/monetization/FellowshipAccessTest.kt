package app.baluard.mobile.monetization

import app.baluard.mobile.BuildConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FellowshipAccessTest {
    private val certificate = "123".toByteArray()
    private val certificateSha256 = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"

    @Test
    fun `build config fellowship pins are well formed`() {
        val pins = BuildConfig.FELLOWSHIP_CERTIFICATES_SHA256.split(",").map(String::trim)

        assertTrue(pins.isNotEmpty())
        assertTrue(pins.all { Regex("[0-9a-fA-F]{64}").matches(it) })
        assertTrue(pins.contains("1856707D5517FF046FC76E780C63585FA62ECA8FE4BE53B0FE705E6E2BFC4D31"))
    }

    @Test
    fun `the pinned fellowship certificate unlocks`() {
        assertTrue(fellowshipCertificateMatches(listOf(certificate), certificateSha256))
    }

    @Test
    fun `another signer cannot impersonate fellowship`() {
        assertFalse(fellowshipCertificateMatches(listOf("not-fellowship".toByteArray()), certificateSha256))
    }

    @Test
    fun `a rotated signing history accepts the pinned certificate`() {
        assertTrue(fellowshipCertificateMatches(listOf("rotated".toByteArray(), certificate), certificateSha256))
    }

    @Test
    fun `missing certificates and malformed pins fail closed`() {
        assertFalse(fellowshipCertificateMatches(emptyList(), certificateSha256))
        assertFalse(fellowshipCertificateMatches(listOf(certificate), ""))
        assertFalse(fellowshipCertificateMatches(listOf(certificate), "not-a-sha256"))
    }

    @Test
    fun `any pinned play signing certificate unlocks`() {
        val otherCertificate = "456".toByteArray()
        val otherSha256 = "b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"

        assertTrue(
            fellowshipSigningMatches(
                currentSigners = listOf(otherCertificate),
                signingHistory = listOf(otherCertificate),
                hasMultipleSigners = false,
                expectedSha256 = "$certificateSha256,$otherSha256",
            ),
        )
    }

    @Test
    fun `hybrid play signing requires every current signer to be pinned`() {
        val otherCertificate = "456".toByteArray()
        val otherSha256 = "b3a8e0e1f9ab1bfe3a36f231f676f78bb30a519d2b21e6c530c0eee8ebb4a5d0"
        val pins = "$certificateSha256,$otherSha256"

        assertTrue(
            fellowshipSigningMatches(listOf(certificate, otherCertificate), null, true, pins),
        )
        assertFalse(
            fellowshipSigningMatches(
                listOf(certificate, "not-fellowship".toByteArray()),
                null,
                true,
                pins,
            ),
        )
    }

    @Test
    fun `fellowship falls back when play is unavailable but still checks play`() = runTest {
        var playCalled = false

        val result = queryWithFellowship(fellowshipActive = true) {
            playCalled = true
            StoreQuery.Unavailable
        }

        assertEquals(StoreQuery.FellowshipOffline, result)
        assertTrue(playCalled)
    }

    @Test
    fun `a play failure still falls back to fellowship`() = runTest {
        val result = queryWithFellowship(fellowshipActive = true) {
            throw RuntimeException("billing unavailable")
        }

        assertEquals(StoreQuery.FellowshipOffline, result)
    }

    @Test
    fun `play cancellation is not swallowed by fellowship`() = runTest {
        val result = runCatching {
            queryWithFellowship(fellowshipActive = true) {
                throw CancellationException("cancelled")
            }
        }

        assertTrue(result.exceptionOrNull() is CancellationException)
    }

    @Test
    fun `a verified play purchase wins over fellowship`() = runTest {
        val result = queryWithFellowship(fellowshipActive = true) {
            StoreQuery.Purchased(willRenew = false)
        }

        assertEquals(StoreQuery.Purchased(willRenew = false), result)
    }

    @Test
    fun `fellowship covers a definite inactive play result`() = runTest {
        assertEquals(
            StoreQuery.Fellowship,
            queryWithFellowship(fellowshipActive = true) { StoreQuery.NothingActive },
        )
    }

    @Test
    fun `without fellowship the play answer is unchanged`() = runTest {
        assertEquals(
            StoreQuery.Purchased(willRenew = true),
            queryWithFellowship(fellowshipActive = false) { StoreQuery.Purchased(willRenew = true) },
        )
        assertEquals(
            StoreQuery.Unavailable,
            queryWithFellowship(fellowshipActive = false) { StoreQuery.Unavailable },
        )
    }
}
