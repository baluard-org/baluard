package xyz.actitud.baluard.platform

import platform.Foundation.NSURL
import platform.UIKit.UIApplication

/** iOS `actual`: UIApplication.openURL (modern options overload). */
actual fun openUrl(url: String) {
    val nsurl = NSURL.URLWithString(url) ?: return
    UIApplication.sharedApplication.openURL(nsurl, options = emptyMap<Any?, Any>(), completionHandler = null)
}
