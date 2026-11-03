package app.baluard.mobile.platform

/**
 * Platform error log sink (logcat on Android, system log on iOS). For
 * diagnosable failures only; never logs secret material.
 */
expect fun platformLogE(tag: String, message: String, error: Throwable? = null)
