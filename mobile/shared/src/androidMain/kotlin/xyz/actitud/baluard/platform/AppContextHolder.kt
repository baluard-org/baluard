package xyz.actitud.baluard.platform

import android.content.Context

/**
 * Process-wide Android [Context] holder. Compose Multiplatform commonMain code
 * cannot reach `Context`; platform `actual`s that need it (AppPaths, keystore
 * glue) read it from here. MainActivity sets it once in `onCreate`.
 */
object AppContextHolder {
    @Volatile
    private var context: Context? = null

    fun set(context: Context) {
        this.context = context.applicationContext
    }

    /** The application context, or null before MainActivity initialized it. */
    fun get(): Context? = context

    fun require(): Context =
        requireNotNull(context) { "AppContextHolder not initialized (MainActivity.onCreate)" }
}
