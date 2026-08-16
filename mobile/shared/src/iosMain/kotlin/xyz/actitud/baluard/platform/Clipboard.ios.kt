package xyz.actitud.baluard.platform

import platform.UIKit.UIPasteboard

/** iOS `actual`: general pasteboard. */
actual fun copyToClipboard(text: String) {
    UIPasteboard.generalPasteboard.string = text
}
