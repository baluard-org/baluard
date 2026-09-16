package xyz.actitud.baluard.platform

import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri

/**
 * Android actual (plan 2b/S3, mirrors bitwarden-android
 * BrowserThirdPartyAutofillManagerImpl):
 *
 * - Availability: package installed (any Brave release channel).
 * - State: Brave answers `content://<pkg>.AutofillThirdPartyModeContentProvider/
 *   autofill_third_party_mode` with column `autofill_third_party_state`
 *   (int != 0 = third-party autofill on). Provider missing = unknown (null):
 *   the row still shows per Esteban's call, tap deep-links to Brave settings.
 * - Deep link: ACTION_APPLICATION_PREFERENCES scoped to the Brave package,
 *   i.e. the browser's own in-app settings screen.
 */
actual object BrowserAutofillIntegration {

    private val channels = listOf(
        "com.brave.browser",
        "com.brave.browser.beta",
        "com.brave.browser.nightly",
    )
    private const val PROVIDER_SUFFIX = ".AutofillThirdPartyModeContentProvider/autofill_third_party_mode"
    private const val COLUMN = "autofill_third_party_state"

    private fun installedPackage(): String? {
        val context = AppContextHolder.get() ?: return null
        val pm = context.packageManager
        for (pkg in channels) {
            if (runCatching { pm.getPackageInfo(pkg, 0) }.isSuccess) return pkg
        }
        return null
    }

    actual fun isAvailable(): Boolean = installedPackage() != null

    actual fun isEnabled(): Boolean? {
        val pkg = installedPackage() ?: return null
        val context = AppContextHolder.get() ?: return null
        return runCatching {
            context.contentResolver.query(
                Uri.parse("content://$pkg$PROVIDER_SUFFIX"),
                arrayOf(COLUMN),
                null,
                null,
                null,
            )?.use { cursor: Cursor ->
                if (cursor.moveToFirst()) cursor.getInt(0) != 0 else null
            }
        }.getOrNull()
    }

    actual fun openSettings() {
        val pkg = installedPackage() ?: return
        val context = AppContextHolder.get() ?: return
        val intent = Intent(Intent.ACTION_APPLICATION_PREFERENCES).apply {
            addCategory(Intent.CATEGORY_DEFAULT)
            addCategory(Intent.CATEGORY_APP_BROWSER)
            addCategory(Intent.CATEGORY_PREFERENCE)
            setPackage(pkg)
        }
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
