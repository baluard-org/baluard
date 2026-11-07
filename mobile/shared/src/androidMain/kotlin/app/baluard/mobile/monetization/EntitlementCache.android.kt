package app.baluard.mobile.monetization

import app.baluard.mobile.platform.CrossProcessPrefs

private const val KEY = "monetization"

/**
 * Entitlement cache over [CrossProcessPrefs] so the `:autofill` process and the main
 * process agree on one persisted entitlement. Format: `phase;trialEndsMillis|-
 * ;willRenew`. A corrupt line loads as null (Unknown), which locks the gates until
 * the next successful store query rewrites it.
 */
fun androidEntitlementCache(): EntitlementCache = object : EntitlementCache {

    override fun load(): CachedEntitlement? {
        val raw = CrossProcessPrefs.read(KEY) ?: return null
        return runCatching {
            val parts = raw.split(';')
            CachedEntitlement(
                phase = EntitlementPhase.valueOf(parts[0]),
                trialEndsAtEpochMs = parts.getOrNull(1)?.takeIf { it != "-" }?.toLong(),
                willRenew = parts.getOrNull(2) == "true",
            )
        }.getOrNull()
    }

    override fun save(value: CachedEntitlement?) {
        if (value == null) {
            CrossProcessPrefs.remove(KEY)
            return
        }
        val raw = buildString {
            append(value.phase.name)
            append(';')
            append(value.trialEndsAtEpochMs?.toString() ?: "-")
            append(';')
            append(value.willRenew)
        }
        CrossProcessPrefs.write(KEY, raw)
    }
}
