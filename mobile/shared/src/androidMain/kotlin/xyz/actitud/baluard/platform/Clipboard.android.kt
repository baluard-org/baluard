package xyz.actitud.baluard.platform

import android.content.ClipData
import android.content.Context

/** Android `actual`: ClipboardManager via the app context. */
actual fun copyToClipboard(text: String) {
    val ctx = AppContextHolder.get() ?: return
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("Baluard", text))
}
