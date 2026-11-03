package app.baluard.mobile.platform

/**
 * Device-local clipboard auto-clear preference (seconds; 0 = never clear).
 * Deliberately NOT synced: how long THIS device's clipboard holds secrets
 * is a per-device habit, not vault data. Mirrors the SyncConfigStore
 * pattern (androidMain: SharedPreferences; iosMain: stub).
 */
expect class ClipboardPrefs() {
    fun loadSeconds(): Int
    fun saveSeconds(seconds: Int)
}

/** Auto-clear preset (seconds; 0 = never clear). */
data class ClipboardClearPreset(val seconds: Int, val labelKey: String)

/** Presets mirror the desktop/browser extension choice set. */
val clipboardClearPresets = listOf(
    ClipboardClearPreset(0, "settings.clipboardClear.never"),
    ClipboardClearPreset(10, "settings.clipboardClear.10s"),
    ClipboardClearPreset(30, "settings.clipboardClear.30s"),
    ClipboardClearPreset(60, "settings.clipboardClear.60s"),
    ClipboardClearPreset(120, "settings.clipboardClear.120s"),
)

/** i18n label key for a stored seconds value (30s default on unknown). */
fun clipboardClearLabel(seconds: Int): String =
    clipboardClearPresets.firstOrNull { it.seconds == seconds }?.labelKey
        ?: "settings.clipboardClear.30s"
