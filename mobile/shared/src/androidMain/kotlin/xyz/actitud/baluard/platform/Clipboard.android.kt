package xyz.actitud.baluard.platform

import android.content.ClipData
import android.content.Context

/** Android `actual`: ClipboardManager via the app context. */
actual fun copyToClipboard(text: String) {
    val ctx = AppContextHolder.get() ?: return
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
    val clip = android.content.ClipData.newPlainText("Baluard", text)
    // M2: mark the clip sensitive so Android 13+ hides the plaintext from
    // the clipboard preview overlay. Older versions ignore the flag.
    clip.description.extras = android.os.PersistableBundle().apply {
        putBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE, true)
    }
    cm.setPrimaryClip(clip)
}
