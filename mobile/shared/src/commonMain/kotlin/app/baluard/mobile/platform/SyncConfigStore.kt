package app.baluard.mobile.platform

import app.baluard.mobile.sync.SyncConfig

/**
 * Persists the sync settings (plan §3.5) across app restarts.
 * androidMain: SharedPreferences. iosMain: stub (iOS deferred, §1.1).
 */
expect class SyncConfigStore() {
    fun load(): SyncConfig
    fun save(config: SyncConfig)
}
