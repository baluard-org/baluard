package xyz.actitud.baluard.platform

/**
 * iOS `actual` for [BackgroundSyncScheduler]. Stub until the iOS host build
 * (plan §1.1); the real impl uses BGTaskScheduler with the same Rust
 * `backgroundFetch` (fetch-only, no unlock).
 */
actual class BackgroundSyncScheduler {
    actual fun setEnabled(enabled: Boolean, intervalMinutes: Int) {
        // No-op: iOS deferred (Android first, plan §1.1).
    }
}
