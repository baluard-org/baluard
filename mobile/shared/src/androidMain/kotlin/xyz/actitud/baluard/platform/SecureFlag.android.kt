package xyz.actitud.baluard.platform

import android.view.WindowManager

/**
 * Android `actual`: sets FLAG_SECURE on the current activity window, which
 * blanks the surface in screenshots, the recents preview, and unprivileged
 * screen recording.
 */
actual fun setSecureFlag(enabled: Boolean) {
    val window = (AppContextHolder.get() as? android.app.Activity)?.window ?: return
    if (enabled) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    } else {
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
