package xyz.actitud.baluard.platform

import xyz.actitud.baluard.i18n.t
import kotlin.test.Test
import kotlin.test.assertEquals

class SecurityKeyErrorMessageTest {
    @Test
    fun probeReasonsGetSpecificCopy() {
        assertEquals(
            t("settings.hardwareKeyTimeout"),
            securityKeyErrorMessage(Exception("Connect a compatible security key. (touch-timeout)")),
        )
        assertEquals(
            t("settings.hardwareKeyUvForced"),
            securityKeyErrorMessage(Exception("Connect a compatible security key. (uv-forced)")),
        )
        assertEquals(
            t("settings.hardwareKeyPinRequired"),
            securityKeyErrorMessage(Exception("Connect a compatible security key. (pin-required)")),
        )
    }
}
