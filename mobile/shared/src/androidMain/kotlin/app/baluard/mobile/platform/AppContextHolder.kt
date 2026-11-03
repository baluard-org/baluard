package app.baluard.mobile.platform

import android.content.Context
import androidx.fragment.app.FragmentActivity

/**
 * Process-wide Android [Context] holder. Compose Multiplatform commonMain code
 * cannot reach `Context`; platform `actual`s that need it (AppPaths, keystore
 * glue) read it from here. MainActivity sets it once in `onCreate`.
 */
object AppContextHolder {
    @Volatile
    private var context: Context? = null

    /** The unlock-screen host activity (BiometricPrompt needs an Activity). */
    @Volatile
    private var hostActivity: FragmentActivity? = null

    fun set(context: Context) {
        this.context = context.applicationContext
        try {
            app.baluard.mobile.initDataDir(context.applicationContext.filesDir.absolutePath)
        } catch (e: Throwable) {
            // BALUARD_DATA_DIR unset breaks every data_dir() consumer (CA
            // bundle, providers.json, token fallback) in ways that surface
            // only as unrelated downstream errors. Never swallow silently.
            platformLogE("AppContextHolder", "initDataDir failed", e)
        }
    }

    /** The application context, or null before MainActivity initialized it. */
    fun get(): Context? = context

    fun require(): Context =
        requireNotNull(context) { "AppContextHolder not initialized (MainActivity.onCreate)" }

    /** Set from MainActivity (a FragmentActivity, so BiometricPrompt can host). */
    fun setActivity(activity: FragmentActivity) {
        hostActivity = activity
    }

    /** The current host activity, or null when the app is backgrounded/destroyed. */
    fun activity(): FragmentActivity? = hostActivity

    /** Clear on destroy, but only if the holder still points at [activity]. */
    fun clearActivity(activity: FragmentActivity) {
        if (hostActivity === activity) hostActivity = null
    }
}
