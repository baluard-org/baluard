package app.baluard.mobile.platform

/**
 * Opt-in background sync (plan §3.5): schedule the periodic LOCKED FETCH
 * (git objects only, no unlock — Rust `background_fetch`). Android actual =
 * WorkManager periodic work; iOS actual = stub (iOS deferred, §1.1).
 */
expect class BackgroundSyncScheduler() {
    /** Register (enabled=true) or cancel (enabled=false) the periodic job. */
    fun setEnabled(enabled: Boolean, intervalMinutes: Int)
}
