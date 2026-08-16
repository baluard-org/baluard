package xyz.actitud.baluard.platform

import android.content.Intent
import android.net.Uri

/** Android `actual`: system browser via ACTION_VIEW. */
actual fun openUrl(url: String) {
    val context = AppContextHolder.get() ?: return
    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
}
