package xyz.actitud.baluard.sync

import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.MobileSyncStatus

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
class SyncCoordinator(private val config: SyncConfig = SyncConfig()) {

    /** Vault unlock → immediate pull (if enabled). */
    suspend fun onUnlock(vault: MobileVault) {
        if (config.syncOnUnlock) vault.syncOnUnlock()
    }

    /** CRUD mutation → arm the 5s debounced push (if enabled). */
    suspend fun onMutation(vault: MobileVault) {
        if (config.syncAfterChange) vault.syncOnMutation()
    }

    /** App foreground → pull with the runtime's 10-min guard (if enabled). */
    suspend fun onForeground(vault: MobileVault) {
        if (config.syncOnForeground) vault.syncOnForeground()
    }

    /**
     * App background → FLUSH any pending debounce immediately (mandatory; the OS
     * suspends the process within seconds and would drop the 5s timer).
     */
    suspend fun onBackground(vault: MobileVault) {
        vault.syncOnBackground()
    }

    /** User pull-to-refresh / "Sync now". */
    suspend fun pullNow(vault: MobileVault) = vault.syncPullNow()

    /** Host-scheduled 30s probe while Offline + foregrounded. */
    suspend fun offlineTick(vault: MobileVault) = vault.syncOfflineTick()

    /** Coordinator status for the sync indicator. */
    suspend fun status(vault: MobileVault): MobileSyncStatus = vault.syncStatus()
}

/**
 * Sync settings (plan §3.5). Defaults match the desktop: sync on unlock +
 * after change + on foreground ON, background sync OFF, Wi-Fi-only advisory.
 * Persisted via DataStore on the host; this is the in-memory default.
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
