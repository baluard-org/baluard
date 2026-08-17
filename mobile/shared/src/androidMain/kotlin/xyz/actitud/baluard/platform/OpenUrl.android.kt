package xyz.actitud.baluard.platform

import android.content.Intent
import android.net.Uri

/** Android `actual`: system browser via ACTION_VIEW.
 *
 * AppContextHolder hands out the APPLICATION context; launching from it
 * without FLAG_ACTIVITY_NEW_TASK throws AndroidRuntimeException ("calling
 * startActivity from outside of an Activity context") and kills the app —
 * seen on the device-flow "Open browser" button. The flag makes the launch
 * legal from any context and is what we want anyway (browser opens over the
 * app, back gesture returns to it).
 */
actual fun openUrl(url: String) {
    val context = AppContextHolder.get() ?: return
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    runCatching { context.startActivity(intent) }
}
