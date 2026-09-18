package xyz.actitud.baluard.i18n

import kotlin.test.Test
import kotlin.test.assertTrue

class I18nParityTest {
    @Test
    fun enAndEsHaveExactSameKeys() {
        val missingInEs = EN.keys - ES.keys
        val missingInEn = ES.keys - EN.keys
        assertTrue(missingInEs.isEmpty(), "Keys missing in ES: $missingInEs")
        assertTrue(missingInEn.isEmpty(), "Keys missing in EN: $missingInEn")
    }

    @Test
    fun enAndPtHaveExactSameKeys() {
        val missingInPt = EN.keys - PT.keys
        val missingInEn = PT.keys - EN.keys
        assertTrue(missingInPt.isEmpty(), "Keys missing in PT: $missingInPt")
        assertTrue(missingInEn.isEmpty(), "Keys missing in EN: $missingInEn")
    }
}
