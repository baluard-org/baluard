package app.baluard.mobile.platform

import android.service.autofill.FillRequest
import android.service.autofill.SaveInfo
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The save-capture trigger must mirror Bitwarden: the aggressive
 * all-views-invisible commit only for compatibility-mode sessions, never
 * for native ones (the Open Baluard save-prompt bug, 2026-11-17).
 */
class SaveFlagsTest {

    @Test
    fun compatRequestCarriesSaveOnAllViewsInvisible() {
        assertEquals(
            SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE,
            SaveFlags.forRequest(FillRequest.FLAG_COMPATIBILITY_MODE_REQUEST),
        )
    }

    @Test
    fun nativeRequestCarriesNoSaveFlag() {
        assertEquals(0, SaveFlags.forRequest(0))
    }

    @Test
    fun mixedFlagsCarryTheSaveFlagOnlyForTheCompatBit() {
        val other = FillRequest.FLAG_COMPATIBILITY_MODE_REQUEST.inv()
        assertEquals(
            SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE,
            SaveFlags.forRequest(FillRequest.FLAG_COMPATIBILITY_MODE_REQUEST or other),
        )
        assertEquals(0, SaveFlags.forRequest(other))
    }
}
