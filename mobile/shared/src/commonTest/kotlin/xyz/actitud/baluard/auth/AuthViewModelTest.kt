package xyz.actitud.baluard.auth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import xyz.actitud.baluard.data.UnlockResult
import xyz.actitud.baluard.i18n.t

/**
 * H11: one error-to-outcome map for every unlock path. The UI must never
 * string-match raw Rust English itself, and a chip-gone unlock must read
 * as a key prompt, never as "wrong password".
 */
class AuthViewModelTest {

    @Test
    fun wrong_password_classifies_as_a_credential_failure() {
        val result = classifyUnlockError(
            xyz.actitud.baluard.BaluardException.WrongPassword(),
        )
        assertTrue(result is UnlockResult.WrongPassword)
    }

    @Test
    fun chip_gone_classifies_as_a_key_prompt_not_wrong_password() {
        val result = classifyUnlockError(
            xyz.actitud.baluard.BaluardException.SecurityKey(
                "this vault is guarded by this device's security chip and the chip is unavailable",
            ),
        )
        assertTrue(result is UnlockResult.SecurityKey)
        assertEquals(t("settings.hardwareKeyHold"), result.message)
    }

    @Test
    fun touch_timeout_keeps_its_localized_key_copy() {
        val result = classifyUnlockError(
            xyz.actitud.baluard.BaluardException.SecurityKey("not tapped in time"),
        )
        assertTrue(result is UnlockResult.SecurityKey)
        assertEquals(t("settings.hardwareKeyTimeout"), result.message)
    }

    @Test
    fun unrelated_busy_errors_do_not_become_security_key_failures() {
        val result = classifyUnlockError(RuntimeException("database busy"))
        assertTrue(result is UnlockResult.Failure)
        assertEquals(t("login.unlockFailed"), result.message)
    }

    @Test
    fun unknown_errors_stay_generic_and_localized() {
        val result = classifyUnlockError(RuntimeException("io mishap detail"))
        assertTrue(result is UnlockResult.Failure)
        assertEquals(t("login.unlockFailed"), result.message)
    }
}
