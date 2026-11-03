package app.baluard.mobile.platform

import java.util.Locale

/** Android `actual`: the system locale's two-letter language code. */
actual fun platformLanguage(): String = Locale.getDefault().language
