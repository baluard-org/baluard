package xyz.actitud.baluard.platform

import java.util.Locale

/** Android `actual`: the system locale's two-letter language code. */
actual fun platformLanguage(): String = Locale.getDefault().language
