package app.baluard.mobile.platform

import platform.CoreServices.kUTTypeUTF8PlainText
import platform.Foundation.NSDate
import platform.UIKit.UIPasteboard
import platform.UIKit.UIPasteboardOptionExpirationDate
import platform.UIKit.UIPasteboardOptionLocalOnly

/**
 * iOS `actual`: general pasteboard, marked local-only with an OS-side
 * expiration. `localOnly` keeps the secret off Universal Clipboard (it
 * would otherwise sync to the user's other Apple devices), and the
 * expiration is enforced by iOS, so it fires even though the app process
 * suspends in the background — a `delay`-based clear would never run.
 */
actual fun copyToClipboard(text: String) {
    val pb = UIPasteboard.generalPasteboard
    val seconds = ClipboardPrefs().loadSeconds()
    if (seconds <= 0) {
        // "Never" still must not leave the device.
        pb.setItems(
            listOf(mapOf(kUTTypeUTF8PlainText to text)),
            options = mapOf(UIPasteboardOptionLocalOnly to true),
        )
        return
    }
    pb.setItems(
        listOf(mapOf(kUTTypeUTF8PlainText to text)),
        options = mapOf(
            UIPasteboardOptionLocalOnly to true,
            UIPasteboardOptionExpirationDate to NSDate(timeIntervalSinceNow = seconds * 1.0),
        ),
    )
}
