package app.baluard.mobile.monetization

import android.content.Context
import android.content.pm.PackageManager
import app.baluard.mobile.BuildConfig
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException

private const val FELLOWSHIP_PACKAGE = "app.baluard.mobile.fellowship"
private val SHA256_HEX = Regex("[0-9a-fA-F]{64}")

internal class FellowshipAccess(context: Context) {
    private val packageManager = context.packageManager

    fun isActive(): Boolean = try {
        @Suppress("DEPRECATION")
        val info = packageManager.getPackageInfo(FELLOWSHIP_PACKAGE, PackageManager.GET_SIGNING_CERTIFICATES)
        val signing = info.signingInfo
        signing != null && fellowshipSigningMatches(
            currentSigners = signing.apkContentsSigners.map { it.toByteArray() },
            signingHistory = signing.signingCertificateHistory?.map { it.toByteArray() },
            hasMultipleSigners = signing.hasMultipleSigners(),
            expectedSha256 = BuildConfig.FELLOWSHIP_CERTIFICATES_SHA256,
        )
    } catch (_: Exception) {
        false
    }
}

internal fun fellowshipCertificateMatches(certificates: List<ByteArray>, expectedSha256: String): Boolean {
    val expectedPins = expectedSha256.split(",").map(String::trim)
    if (expectedPins.any { !SHA256_HEX.matches(it) }) return false
    val expected = expectedPins.map { pin -> pin.chunked(2).map { it.toInt(16).toByte() }.toByteArray() }
    return certificates.any { certificate ->
        val digest = MessageDigest.getInstance("SHA-256").digest(certificate)
        expected.any { pin -> MessageDigest.isEqual(digest, pin) }
    }
}

internal fun fellowshipSigningMatches(
    currentSigners: List<ByteArray>,
    signingHistory: List<ByteArray>?,
    hasMultipleSigners: Boolean,
    expectedSha256: String,
): Boolean {
    if (currentSigners.isEmpty()) return false
    if (!hasMultipleSigners) return fellowshipCertificateMatches(signingHistory.orEmpty(), expectedSha256)
    return currentSigners.all { fellowshipCertificateMatches(listOf(it), expectedSha256) }
}

internal suspend fun queryWithFellowship(
    fellowshipActive: Boolean,
    queryPlay: suspend () -> StoreQuery,
): StoreQuery {
    if (!fellowshipActive) return queryPlay()
    val playResult = try {
        queryPlay()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        StoreQuery.Unavailable
    }
    return when (playResult) {
        is StoreQuery.Purchased, is StoreQuery.TrialActive -> playResult
        StoreQuery.Unavailable -> StoreQuery.FellowshipOffline
        else -> StoreQuery.Fellowship
    }
}
