package xyz.actitud.baluard.platform

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.view.accessibility.AccessibilityManager

/**
 * Android actual. The system readback matches OUR service only (package +
 * AccessibilityServiceInfo.FEEDBACK_GENERIC list), mirroring Bitwarden's
 * AccessibilityManager-first check.
 */
actual object AccessibilityFill {

    private const val FILE = "baluard_autofill_prefs"
    private const val KEY = "a11y_fill_enabled"

    private fun prefs() = AppContextHolder.get()
        ?.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    actual fun enabled(): Boolean = prefs()?.getBoolean(KEY, false) ?: false

    actual fun setEnabled(enabled: Boolean) {
        prefs()?.edit()?.putBoolean(KEY, enabled)?.apply()
    }

    actual fun serviceEnabledInSystem(): Boolean = runCatching {
        val context = AppContextHolder.get() ?: return false
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return false
        am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_GENERIC)
            .any { it.resolveInfo?.serviceInfo?.packageName == context.packageName }
    }.getOrDefault(false)

    actual fun openSystemA11ySettings() {
        val context = AppContextHolder.get() ?: return
        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
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
