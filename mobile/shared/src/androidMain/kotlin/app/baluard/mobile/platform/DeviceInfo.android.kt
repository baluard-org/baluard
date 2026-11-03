package app.baluard.mobile.platform

import android.os.Build

/** Android `actual`: Build.MODEL, manufacturer prefixed when not already there. */
actual fun deviceDisplayName(): String {
    val model = Build.MODEL?.trim().orEmpty()
    if (model.isEmpty()) return ""
    val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
    return if (manufacturer.isEmpty() || model.startsWith(manufacturer, ignoreCase = true)) {
        model
    } else {
        "$manufacturer $model"
    }
}
