package xyz.actitud.baluard.platform

import xyz.actitud.baluard.sync.SyncConfig

/**
 * Persists the sync settings (plan §3.5) across app restarts.
 * androidMain: SharedPreferences. iosMain: stub (iOS deferred, §1.1).
 */
expect class SyncConfigStore() {
    fun load(): SyncConfig
    fun save(config: SyncConfig)
}
