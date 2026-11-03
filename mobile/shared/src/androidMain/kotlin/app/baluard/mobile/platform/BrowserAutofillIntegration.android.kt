package app.baluard.mobile.platform

import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.Uri

/**
 * Android actual (mirrors bitwarden-android
 * BrowserThirdPartyAutofillManagerImpl): each browser answers
 * `content://<pkg>.AutofillThirdPartyModeContentProvider/autofill_third_party_mode`
 * with column `autofill_third_party_state` (int != 0 = on). Provider
 * missing = unknown (null); deep link = ACTION_APPLICATION_PREFERENCES
 * scoped to the browser package.
 */
actual object BrowserAutofillIntegration {

    private class Spec(val id: String, val packages: List<String>) {
        fun installed(): String? {
            val context = AppContextHolder.get() ?: return null
            for (pkg in packages) {
                if (runCatching { context.packageManager.getPackageInfo(pkg, 0) }.isSuccess) return pkg
            }
            return null
        }
    }

    // Order = row order in Settings. Channel lists mirror Bitwarden's.
    private val specs = listOf(
        Spec("brave", listOf("com.brave.browser", "com.brave.browser.beta", "com.brave.browser.nightly")),
        Spec("chrome", listOf("com.android.chrome", "com.chrome.beta")),
        Spec("vivaldi", listOf("com.vivaldi.browser")),
    )

    private const val PROVIDER_SUFFIX = ".AutofillThirdPartyModeContentProvider/autofill_third_party_mode"
    private const val COLUMN = "autofill_third_party_state"

    private fun probe(pkg: String): Boolean? {
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

    actual fun browsers(): List<BrowserIntegration> = specs.mapNotNull { spec ->
        val pkg = spec.installed() ?: return@mapNotNull null
        BrowserIntegration(id = spec.id, available = true, enabled = probe(pkg))
    }

    actual fun openSettings(id: String) {
        val spec = specs.firstOrNull { it.id == id } ?: return
        val pkg = spec.installed() ?: return
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
