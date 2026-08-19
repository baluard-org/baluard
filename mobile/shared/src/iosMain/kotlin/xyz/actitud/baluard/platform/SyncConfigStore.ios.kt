package xyz.actitud.baluard.platform

import xyz.actitud.baluard.sync.SyncConfig

/**
 * iOS `actual` for [SyncConfigStore]. Stub until the iOS host build
 * (plan §1.1: Android first). The real impl persists to NSUserDefaults
 * (or Keychain if any field is ever security-relevant — none are: they
 * are advisory toggles only).
 */
actual class SyncConfigStore {
    private var cached: SyncConfig = SyncConfig()

    actual fun load(): SyncConfig = cached

    actual fun save(config: SyncConfig) {
        cached = config
    }
}
