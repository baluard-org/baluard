package xyz.actitud.baluard.platform

import android.content.Intent

actual fun openCredentialProviderSettings(): Boolean {
    val context = AppContextHolder.get() ?: return false
    return runCatching {
        context.startActivity(
            Intent("android.settings.CREDENTIAL_PROVIDER_SETTINGS")
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
        true
    }.getOrDefault(false)
}
