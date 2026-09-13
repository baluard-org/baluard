package xyz.actitud.baluard.platform

import android.content.ClipData
import android.content.Context
import android.os.Handler
import android.os.Looper

/** Android `actual`: ClipboardManager via the app context + auto-clear. */
actual fun copyToClipboard(text: String) {
    val ctx = AppContextHolder.get() ?: return
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
    val clip = ClipData.newPlainText("Baluard", text)
    // M2: mark the clip sensitive so Android 13+ hides the plaintext from
    // the clipboard preview overlay. Older versions ignore the flag.
    clip.description.extras = android.os.PersistableBundle().apply {
        putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
    }
    cm.setPrimaryClip(clip)
    scheduleAutoClear(cm, ctx, text)
}

/**
 * Desktop-parity auto-clear: after the configured delay, wipe the clipboard
 * ONLY if it still holds our value (a newer user copy is never stomped).
 * Reading back our own clip is toast-free on Android 13+; the system paste
 * notice fires only for clips this app did not place.
 *
 * Concurrent copies need no timer cancellation: a stale timer compares its
 * old value against the current clip, misses, and does nothing — the newest
 * copy's timer is the only one that can match.
 */
private fun scheduleAutoClear(cm: android.content.ClipboardManager, ctx: Context, text: String) {
    val seconds = runCatching { ClipboardPrefs().loadSeconds() }.getOrDefault(30)
    if (seconds <= 0) return
    Handler(Looper.getMainLooper()).postDelayed({
        runCatching {
            val current = cm.primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString()
            if (current == text) cm.clearPrimaryClip()
        }.onFailure { platformLogE("Clipboard", "auto-clear failed", it) }
    }, seconds * 1000L)
}
