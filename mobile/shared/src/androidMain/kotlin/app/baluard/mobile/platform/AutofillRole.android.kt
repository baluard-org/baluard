package app.baluard.mobile.platform

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager

/**
 * Android actual: status comes from the framework AutofillManager
 * (hasEnabledAutofillServices is true only while THIS app is the enabled
 * provider). The role request opens the system picker for this package;
 * a missing activity host falls back to launching it as a new task from
 * the app context. Every failure leaves the UI in its current state.
 */
actual object AutofillRole {

    actual fun isSupported(): Boolean = true

    actual fun isEnabled(): Boolean = runCatching {
        val context = AppContextHolder.get() ?: return false
        context.getSystemService(AutofillManager::class.java)
            ?.hasEnabledAutofillServices() == true
    }.getOrDefault(false)

    actual fun requestRole() {
        val context = AppContextHolder.get() ?: return
        val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).apply {
            data = Uri.parse("package:${context.packageName}")
        }
        // Prefer the foreground activity (regular result screen). No activity
        // (settings opened from an odd state) still works with NEW_TASK.
        val activity = AppContextHolder.activity()
        runCatching {
            if (activity != null) {
                activity.startActivity(intent)
            } else {
                context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
        }
    }
}
