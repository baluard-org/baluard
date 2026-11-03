package app.baluard.mobile.passkeys

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Pure origin-validation rules for the Android credential provider (plan
 * §7). No Android imports: everything here is testable from commonTest and
 * the androidApp shell wires PackageManager/assets/fetchers around it.
 *
 * Two validation paths, both fail-closed:
 * - Privileged callers (browsers): the bundled trusted-caller allowlists
 *   answer ONLY "is this package+cert a browser we trust to assert web
 *   origins?" — the populated origin then stands; rp-id containment is the
 *   normal WebAuthn rule ([rpIdCoversOriginHost]).
 * - Unprivileged native apps: the RP must publish a Digital Asset Links
 *   statement granting delegate_permission/common.get_login_creds to the
 *   caller's package + signing-cert fingerprint.
 */
object OriginRules {
    /** The one DAL relation that grants credential access (developer.android.com). */
    const val DAL_CREDENTIAL_RELATION: String = "delegate_permission/common.get_login_creds"

    /** Cache a successful DAL lookup for an hour; failures for a minute. */
    const val DAL_SUCCESS_TTL_MS: Long = 60 * 60 * 1000L
    const val DAL_FAILURE_TTL_MS: Long = 60 * 1000L

    private val json = Json { ignoreUnknownKeys = true }

    /** Package names accepted as privileged from a Google-format allowlist. */
    fun allowlistPackages(allowlistJson: String): Set<String> =
        runCatching {
            json.parseToJsonElement(allowlistJson).jsonObject["apps"]?.jsonArray
                ?.mapNotNull { app ->
                    (app as? JsonObject)?.get("info")?.jsonObject?.get("package_name")
                        ?.jsonPrimitive?.content
                }
                ?.toSet()
        }.getOrNull().orEmpty()

    /**
     * True when [statementsJson] (the parsed assetlinks.json) grants
     * [DAL_CREDENTIAL_RELATION] to [packageName] with [fingerprintHex]
     * (colon-separated uppercase hex, as [fingerprintHex] is produced by the
     * platform shell from the signing cert). Fingerprints compare
     * colon-stripped and case-insensitively: assetlinks files are published
     * colon-separated, the platform digest can arrive either way.
     */
    fun assetLinksGrant(
        statementsJson: String,
        packageName: String,
        fingerprintHex: String,
    ): Boolean = runCatching {
        val statements = json.parseToJsonElement(statementsJson).jsonArray
        val wanted = normalizeFingerprint(fingerprintHex)
        if (wanted.isEmpty()) return false
        statements.any { statement ->
            val obj = statement as? JsonObject ?: return@any false
            // relation is a LIST in published assetlinks.json; grant only
            // when the credential relation is among them.
            val relations = (obj["relation"] as? JsonArray)
                ?.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                ?: return@any false
            if (DAL_CREDENTIAL_RELATION !in relations) return@any false
            val target = obj["target"]?.jsonObject ?: return@any false
            if (target["namespace"]?.jsonPrimitive?.content != "android_app") return@any false
            if (target["package_name"]?.jsonPrimitive?.content != packageName) return@any false
            val shaList = (target["sha256_cert_fingerprints"] as? JsonArray)
                ?.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
                ?: return@any false
            shaList.any { normalizeFingerprint(it) == wanted }
        }
    }.getOrDefault(false)

    /**
     * SSRF guard for the DAL fetch target: the host must be a public DNS
     * name. IP literals and local/private names are refused except the
     * [allowLocal] debug affordance (§12, E2E on loopback).
     */
    fun isFetchableHost(host: String, allowLocal: Boolean): Boolean {
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty()) return false
        // Loopback shape is fetchable only under the debug affordance.
        if (isLocalRpHost(h, true)) return allowLocal
        if (h.contains(':')) return false // non-loopback IPv6 literal
        if (h.endsWith(".local") || h.endsWith(".internal")) return false
        return !Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(h)
    }

    /** Loopback detection shared by the SSRF guard and the E2E native-app
     *  grant: localhost, .localhost, ::1, and 127/8 under [allowLocal]. */
    fun isLocalRpHost(host: String, allowLocal: Boolean): Boolean {
        val h = host.trim().trimEnd('.').lowercase()
        if (h.isEmpty()) return false
        if (h == "localhost" || h.endsWith(".localhost")) return allowLocal
        if (h.contains(':')) return allowLocal && (h == "[::1]" || h == "::1") // IPv6 literal
        if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(h)) {
            if (!allowLocal) return false
            val octets = h.split('.').map { it.toIntOrNull() ?: return false }
            if (octets.any { it !in 0..255 }) return false
            return octets[0] == 127
        }
        return false
    }

    /**
     * Normal WebAuthn rp-id containment for listing: the origin host equals
     * the rp id or is a subdomain of it. The ceremony-side effective_rp_id
     * (public-suffix aware) remains the authority; this pre-check only
     * decides whether an entry is listed.
     */
    fun rpIdCoversOriginHost(rpId: String, originHost: String): Boolean {
        val rp = rpId.trim().trimEnd('.').lowercase()
        val host = originHost.trim().trimEnd('.').lowercase()
        if (rp.isEmpty() || host.isEmpty()) return false
        return host == rp || host.endsWith(".$rp")
    }

    private fun normalizeFingerprint(hex: String): String =
        hex.replace(":", "").replace("-", "").lowercase()
}
