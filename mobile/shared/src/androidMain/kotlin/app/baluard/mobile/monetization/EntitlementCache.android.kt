package app.baluard.mobile.monetization

import app.baluard.mobile.platform.CrossProcessPrefs

private const val KEY = "monetization"

/**
 * Entitlement cache over [CrossProcessPrefs] so the `:autofill` process and the main
 * process agree on one persisted entitlement. The line format lives in the shared
 * [EntitlementCacheCodec]; a corrupt line loads as null (Unknown), which locks the
 * gates until the next successful store query rewrites it.
 */
fun androidEntitlementCache(): EntitlementCache = object : EntitlementCache {

    override fun load(): CachedEntitlement? =
        CrossProcessPrefs.read(KEY)?.let(EntitlementCacheCodec::decode)

    override fun save(value: CachedEntitlement?) {
        if (value == null) {
            CrossProcessPrefs.remove(KEY)
            return
        }
        CrossProcessPrefs.write(KEY, EntitlementCacheCodec.encode(value))
    }
}
