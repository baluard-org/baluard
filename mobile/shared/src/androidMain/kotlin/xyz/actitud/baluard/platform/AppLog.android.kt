package xyz.actitud.baluard.platform

import android.util.Log

/** Android `actual`: logcat with stack trace. */
actual fun platformLogE(tag: String, message: String, error: Throwable?) {
    if (error != null) {
        Log.e(tag, message, error)
    } else {
        Log.e(tag, message)
    }
}
