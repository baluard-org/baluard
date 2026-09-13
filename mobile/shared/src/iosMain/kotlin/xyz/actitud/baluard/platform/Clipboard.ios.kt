package xyz.actitud.baluard.platform

import kotlinx.coroutines.MainScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import platform.UIKit.UIPasteboard

/** iOS `actual`: general pasteboard + auto-clear. */
actual fun copyToClipboard(text: String) {
    val pb = UIPasteboard.generalPasteboard
    pb.string = text

    // Desktop-parity auto-clear: wipe only if the pasteboard still holds
    // our value. Reading back same-app content never triggers the iOS
    // paste permission prompt (that is for cross-app reads only).
    val seconds = ClipboardPrefs().loadSeconds()
    if (seconds <= 0) return
    MainScope().launch {
        delay(seconds * 1000L)
        if (pb.string == text) pb.string = ""
    }
}
