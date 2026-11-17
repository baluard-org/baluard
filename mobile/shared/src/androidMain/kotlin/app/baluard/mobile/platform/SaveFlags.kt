package app.baluard.mobile.platform

import android.service.autofill.FillRequest
import android.service.autofill.SaveInfo

/**
 * Save-capture trigger policy: the aggressive all-views-invisible commit
 * belongs to compatibility-mode sessions only (Bitwarden parity). On
 * native responses the framework tracks view visibility itself, and
 * forcing the flag makes the save dialog fire on any view transition -
 * even when nothing was submitted (the "asks to save every time" bug).
 */
object SaveFlags {
    fun forRequest(flags: Int): Int =
        if (flags and FillRequest.FLAG_COMPATIBILITY_MODE_REQUEST != 0) {
            SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE
        } else {
            0
        }
}
