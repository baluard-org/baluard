package app.baluard.mobile.platform

import androidx.credentials.CredentialManager
import android.os.Build

/**
 * Opens the system's default credential-provider picker. The only supported
 * route is CredentialManager's settings pending intent: the naive settings
 * action string ("android.settings.CREDENTIAL_PROVIDER_SETTINGS") does not
 * exist in the platform, so startActivity silently threw and the row did
 * nothing.
 */
actual fun openCredentialProviderSettings(): Boolean {
    val context = AppContextHolder.get() ?: return false
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return false
    return runCatching {
        CredentialManager.create(context)
            .createSettingsPendingIntent()
            .send()
        true
    }.getOrDefault(false)
}
