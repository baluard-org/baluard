package xyz.actitud.baluard.platform

/**
 * iOS `actual` for [ClipboardPrefs]. In-memory stub until the iOS host
 * build (plan §1.1), matching the SyncConfigStore stub.
 */
actual class ClipboardPrefs actual constructor() {
    private var seconds: Int = DEFAULT

    actual fun loadSeconds(): Int = seconds

    actual fun saveSeconds(seconds: Int) {
        this.seconds = seconds.coerceIn(0, MAX)
    }

    private companion object {
        const val DEFAULT = 30
        const val MAX = 600
    }
}
