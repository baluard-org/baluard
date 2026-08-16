package xyz.actitud.baluard.platform

import platform.Foundation.NSURL
import platform.UIKit.UIApplication
import platform.UIKit.UIColor

/** iOS `actual`: UIApplication.openURL. */
actual fun openUrl(url: String) {
    val nsurl = NSURL.URLWithString(url) ?: return
    UIApplication.sharedApplication.openURL(nsurl)
}
