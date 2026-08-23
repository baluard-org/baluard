package xyz.actitud.baluard.platform

import android.view.WindowManager

/**
 * Android `actual`: sets FLAG_SECURE on the current activity window, which
 * blanks the surface in screenshots, the recents preview, and unprivileged
 * screen recording.
 */
actual fun setSecureFlag(enabled: Boolean) {
    // M1 fix: use the activity holder, not the application context — the
    // previous `get() as? Activity` cast always failed (applicationContext is
    // never an Activity), making this a silent no-op. MainActivity populates
    // the holder in onCreate; a null here means we run pre-onCreate and the
    // app-wide flag set there covers the window anyway.
    val window = AppContextHolder.activity()?.window ?: return
    if (enabled) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    } else {
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
