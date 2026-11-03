package app.baluard.mobile.settings

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import app.baluard.mobile.MobileSyncStatus
import app.baluard.mobile.MobileVault
import app.baluard.mobile.sync.SyncConfig
import app.baluard.mobile.sync.SyncCoordinator

/**
 * Holds sync settings (plan §3.5) + the live coordinator status for the
 * SettingsScreen. The config is in-memory here; the host persists to DataStore
 * and rehydrates on app start.
 */
class SettingsViewModel(initial: SyncConfig = SyncConfig()) {
    private val _config = MutableStateFlow(initial)
    val config: StateFlow<SyncConfig> = _config.asStateFlow()

    private val _status = MutableStateFlow(MobileSyncStatus(false, "idle", null, 0u))
    val status: StateFlow<MobileSyncStatus> = _status.asStateFlow()

    fun setSyncOnUnlock(v: Boolean) { _config.value = _config.value.copy(syncOnUnlock = v) }
    fun setSyncAfterChange(v: Boolean) { _config.value = _config.value.copy(syncAfterChange = v) }
    fun setSyncOnForeground(v: Boolean) { _config.value = _config.value.copy(syncOnForeground = v) }
    fun setBackgroundSync(v: Boolean) { _config.value = _config.value.copy(backgroundSyncEnabled = v) }
    fun setWifiOnly(v: Boolean) { _config.value = _config.value.copy(wifiOnly = v) }

    suspend fun refresh(vault: MobileVault, coordinator: SyncCoordinator) {
        _status.value = coordinator.status(vault)
    }
}
