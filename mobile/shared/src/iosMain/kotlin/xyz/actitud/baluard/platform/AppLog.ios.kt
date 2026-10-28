package xyz.actitud.baluard.platform

import platform.Foundation.NSLog

/** iOS `actual`: system log. */
actual fun platformLogE(tag: String, message: String, error: Throwable?) {
    val suffix = error?.let { ": $it" } ?: ""
    NSLog("%@", "$tag: $message$suffix")
}
