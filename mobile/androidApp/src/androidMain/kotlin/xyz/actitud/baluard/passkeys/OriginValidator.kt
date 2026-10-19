package xyz.actitud.baluard.passkeys

import android.content.Context
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import xyz.actitud.baluard.BuildConfig
import xyz.actitud.baluard.passkeys.OriginRules.assetLinksGrant
import xyz.actitud.baluard.passkeys.OriginRules.allowlistPackages
import xyz.actitud.baluard.passkeys.OriginRules.isFetchableHost
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import android.util.Base64

/** The ceremony origin a validated caller may assert, and its shape. */
sealed interface OriginDecision {
    /** Trusted browser: the RP's web origin (https URL string). */
    data class Web(val origin: String) : OriginDecision

    /** Native app with a DAL grant: the clientDataJSON origin string RPs verify. */
    data class Android(val origin: String) : OriginDecision

    data class Refused(val reason: String) : OriginDecision
}

/**
 * Fail-closed origin rulebook (plan §7): bundled trusted-caller allowlists
 * for privileged callers (the populated origin stands, rp-id containment is
 * the ceremony's job), live Digital Asset Links for unprivileged native
 * apps. A stale allowlist refuses new browser builds visibly — never a
 * pass-through.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class OriginValidator(
    private val context: Context,
    private val fetcher: AssetLinkFetcher = HttpAssetLinkFetcher(),
    private val nowMs: () -> Long = System::currentTimeMillis,
    // E2E affordance: loopback origins/fetch targets only in debug builds.
    private val allowLocal: Boolean = BuildConfig.BALUARD_E2E || BuildConfig.DEBUG,
) {
    private val dalCache = ConcurrentHashMap<String, CacheEntry>()

    fun validateOrigin(relyingPartyId: String, callingAppInfo: CallingAppInfo): OriginDecision {
        val fingerprint = callingAppInfo.signatureFingerprintHex()
        if (fingerprint == null) {
            return OriginDecision.Refused("multi-signer callers are not supported")
        }
        for (asset in ALLOWLIST_ASSETS) {
            val json = readAsset(asset.file) ?: continue
            if (callingAppInfo.packageName !in allowlistPackages(json)) continue
            // androidx derives the origin from the matching signature; a
            // package hit without one throws.
            return runCatching {
                val origin = callingAppInfo.getOrigin(json)
                if (origin.isNullOrEmpty()) {
                    OriginDecision.Refused("allowlisted package has no matching signature")
                } else if (asset.verifiedSource) {
                    // Verified browser list: the populated origin trivially
                    // matches the rp id after allowlist membership.
                    OriginDecision.Web("https://$relyingPartyId")
                } else {
                    OriginDecision.Web(origin)
                }
            }.getOrElse {
                OriginDecision.Refused("allowlist signature mismatch: ${it.javaClass.simpleName}")
            }
        }
        return validateNativeApp(relyingPartyId, callingAppInfo, fingerprint)
    }

    private fun validateNativeApp(
        relyingPartyId: String,
        callingAppInfo: CallingAppInfo,
        fingerprint: String,
    ): OriginDecision {
        if (!isFetchableHost(relyingPartyId, allowLocal)) {
            return OriginDecision.Refused("rp host is not a public name")
        }
        val origin = "android:apk-key-hash:" +
            Base64.encodeToString(
                MessageDigest.getInstance("SHA-256")
                    .digest(callingAppInfo.signingCertBytes()),
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
            )
        val cacheKey = "$relyingPartyId|${callingAppInfo.packageName}|$fingerprint"
        dalCache[cacheKey]?.let { entry ->
            val ttl = if (entry.granted) OriginRules.DAL_SUCCESS_TTL_MS else OriginRules.DAL_FAILURE_TTL_MS
            if (nowMs() - entry.at <= ttl) {
                return if (entry.granted) OriginDecision.Android(origin)
                else OriginDecision.Refused("no DAL statement (cached)")
            }
        }
        val granted = runCatching {
            val body = fetcher.fetchAssetLinks(relyingPartyId)
            assetLinksGrant(body, callingAppInfo.packageName, fingerprint)
        }.getOrDefault(false)
        dalCache[cacheKey] = CacheEntry(nowMs(), granted)
        return if (granted) OriginDecision.Android(origin)
        else OriginDecision.Refused("no DAL statement for ${callingAppInfo.packageName}")
    }

    private fun readAsset(name: String): String? = runCatching {
        context.assets.open(name).use { it.readBytes().decodeToString() }
    }.getOrNull()

    private data class CacheEntry(val at: Long, val granted: Boolean)

    private companion object {
        /** Chromium-derived lists (Bitwarden-bundled copies; refresh at release). */
        data class Allowlist(val file: String, val verifiedSource: Boolean)

        val ALLOWLIST_ASSETS = listOf(
            Allowlist("fido2_privileged_google.json", verifiedSource = true),
            Allowlist("fido2_privileged_community.json", verifiedSource = false),
        )
    }
}

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
private fun CallingAppInfo.signingCertBytes(): ByteArray {
    val info = signingInfo
    check(!info.hasMultipleSigners()) { "multiple signers" }
    return info.apkContentsSigners.first().toByteArray()
}

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
fun CallingAppInfo.signatureFingerprintHex(): String? {
    if (signingInfo.hasMultipleSigners()) return null
    val digest = MessageDigest.getInstance("SHA-256")
        .digest(signingInfo.apkContentsSigners.first().toByteArray())
    return digest.joinToString(":") { "%02X".format(it) }
}
