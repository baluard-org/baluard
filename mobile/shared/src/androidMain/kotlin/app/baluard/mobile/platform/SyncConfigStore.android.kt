package app.baluard.mobile.platform

import android.content.Context
import app.baluard.mobile.sync.SyncConfig

/**
 * SharedPreferences-backed persistence for sync settings (plan §3.5).
 * DataStore was considered; SharedPreferences is synchronous, dependency-free,
 * and the config is 7 scalars written on toggle changes only.
 */
actual class SyncConfigStore {
    private fun prefs(): android.content.SharedPreferences =
        AppContextHolder.require()
            .getSharedPreferences("baluard_sync_config", Context.MODE_PRIVATE)

    actual fun load(): SyncConfig {
        val p = prefs()
        return SyncConfig(
            syncOnUnlock = p.getBoolean("syncOnUnlock", true),
            syncAfterChange = p.getBoolean("syncAfterChange", true),
            syncOnForeground = p.getBoolean("syncOnForeground", true),
            backgroundSyncEnabled = p.getBoolean("backgroundSyncEnabled", false),
            backgroundIntervalMinutes = p.getInt("backgroundIntervalMinutes", 30).coerceAtLeast(15),
            wifiOnly = p.getBoolean("wifiOnly", true),
            offlineRetryForegroundSecs = p.getInt("offlineRetryForegroundSecs", 30),
        )
    }

    actual fun save(config: SyncConfig) {
        prefs().edit()
            .putBoolean("syncOnUnlock", config.syncOnUnlock)
            .putBoolean("syncAfterChange", config.syncAfterChange)
            .putBoolean("syncOnForeground", config.syncOnForeground)
            .putBoolean("backgroundSyncEnabled", config.backgroundSyncEnabled)
            .putInt("backgroundIntervalMinutes", config.backgroundIntervalMinutes)
            .putBoolean("wifiOnly", config.wifiOnly)
            .putInt("offlineRetryForegroundSecs", config.offlineRetryForegroundSecs)
            .apply()
    }
}
