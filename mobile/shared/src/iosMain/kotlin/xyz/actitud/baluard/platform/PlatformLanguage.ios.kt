package xyz.actitud.baluard.platform

import platform.Foundation.NSLocale
import platform.Foundation.currentLocale
import platform.Foundation.languageCode

/** iOS `actual`: the current NSLocale's two-letter language code. */
actual fun platformLanguage(): String = NSLocale.currentLocale.languageCode
