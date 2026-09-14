package xyz.actitud.baluard.sync

import xyz.actitud.baluard.MobileVaultInterface
import xyz.actitud.baluard.MobileSyncStatus
import xyz.actitud.baluard.platform.Clock
import xyz.actitud.baluard.platform.isMeteredNetwork

/**
 * Maps OS lifecycle hooks to the runtime's sync event surface (plan §3.2/§3.5).
 *
 * Mobile hosts the coordinator WITHOUT a background tokio loop: the OS host
 * (Android `ProcessLifecycleOwner` / iOS `SceneDelegate`) calls these methods
 * from lifecycle callbacks, and they delegate to the runtime's `AutoSyncHandle`
 * event methods (Phase 0 Task #2). One implementation of the debounce /
 * offline-retry / conflict-queue logic; two hosting strategies; zero drift.
 *
 * The two pieces of `background_loop` that mobile MUST reproduce:
 *  - pull-on-unlock + pull-on-foreground (event-driven; the 10-min guard lives
 *    in the runtime so focus flicker collapses to one pull per 10 min)
 *  - the 30s offline retry probe — the host schedules [offlineTick] while the
 *    vault is Offline AND foregrounded (the 30min idle pull is NOT reproduced;
 *    plan §3.5 accepts foreground-as-heartbeat instead).
 */
class SyncCoordinator(
    private var config: SyncConfig = SyncConfig(),
    /** Injectable for tests; default = platform check. */
    private val isMeteredNetwork: () -> Boolean = ::isMeteredNetwork,
) {

    /** Settings changes land here (SettingsScreen toggles). */
    fun updateConfig(new: SyncConfig) {
        config = new
    }

    /**
     * Wi-Fi-only gate (plan §3.5, advisory): the host skips AUTOMATIC sync
     * triggers on metered networks. Explicit user gestures (`pullNow`) and
     * the mandatory background flush always run.
     */
    private fun blockedByNetwork(): Boolean =
        config.wifiOnly && isMeteredNetwork()

    /** Vault unlock → immediate pull (if enabled). */
    suspend fun onUnlock(vault: MobileVaultInterface) {
        if (!config.syncOnUnlock || blockedByNetwork()) return
        vault.syncOnUnlock()
    }

    /** CRUD mutation → arm the 5s debounced push (if enabled). */
    suspend fun onMutation(vault: MobileVaultInterface) {
        if (!config.syncAfterChange || blockedByNetwork()) return
        vault.syncOnMutation()
    }

    /** App foreground → pull with the runtime's 10-min guard (if enabled). */
    suspend fun onForeground(vault: MobileVaultInterface) {
        if (!config.syncOnForeground || blockedByNetwork()) return
        vault.syncOnForeground()
    }

    /**
     * App background → FLUSH any pending debounce immediately (mandatory; the OS
     * suspends the process within seconds and would drop the 5s timer).
     */
    suspend fun onBackground(vault: MobileVaultInterface) {
        vault.syncOnBackground()
    }

    /** User pull-to-refresh / "Sync now". */
    suspend fun pullNow(vault: MobileVaultInterface) = vault.syncPullNow()

    /**
     * Host-scheduled 30s connectivity probe (plan §3.5). The runtime no-ops
     * unless the vault is Offline, so the foreground poll can call this every
     * tick; here we space calls to [SyncConfig.offlineRetryForegroundSecs].
     */
    suspend fun offlineTick(vault: MobileVaultInterface) {
        if (blockedByNetwork()) return
        val now = Clock.currentTimeMillis()
        if (now - lastOfflineProbeMs < config.offlineRetryForegroundSecs * 1000L) return
        lastOfflineProbeMs = now
        vault.syncOfflineTick()
    }
    private var lastOfflineProbeMs = 0L

    /** Coordinator status for the sync indicator. */
    suspend fun status(vault: MobileVaultInterface): MobileSyncStatus = vault.syncStatus()
}

/**
 * Sync settings (plan §3.5). Defaults match the desktop: sync on unlock +
 * after change + on foreground ON, background sync OFF, Wi-Fi-only advisory.
 * Persisted by the host's SyncConfigStore (SharedPreferences on Android).
 */
data class SyncConfig(
    val syncOnUnlock: Boolean = true,
    val syncAfterChange: Boolean = true,
    val syncOnForeground: Boolean = true,
    val backgroundSyncEnabled: Boolean = false,
    val backgroundIntervalMinutes: Int = 30,
    val wifiOnly: Boolean = true,
    val offlineRetryForegroundSecs: Int = 30,
)
