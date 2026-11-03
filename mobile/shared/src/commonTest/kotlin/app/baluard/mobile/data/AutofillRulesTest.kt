package app.baluard.mobile.data

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * H12: the security-key dataset chip appears only when a hardware-sealed
 * vault was the sole candidate. Other vaults' matches and app-to-web
 * suggestions must still fill.
 */
class AutofillRulesTest {

    @Test
    fun chip_shows_when_a_sealed_vault_was_the_only_candidate() {
        assertTrue(securityKeyChipRequired(securityKeyRequired = true, matchCount = 0, suggestionCount = 0))
    }

    @Test
    fun other_vaults_matches_hide_the_chip() {
        assertFalse(securityKeyChipRequired(securityKeyRequired = true, matchCount = 3, suggestionCount = 0))
    }

    @Test
    fun app_to_web_suggestions_also_hide_the_chip() {
        assertFalse(securityKeyChipRequired(securityKeyRequired = true, matchCount = 0, suggestionCount = 2))
    }

    @Test
    fun no_sealed_vault_no_chip() {
        assertFalse(securityKeyChipRequired(securityKeyRequired = false, matchCount = 0, suggestionCount = 0))
    }
}
