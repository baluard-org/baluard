package app.baluard.mobile.platform

import app.baluard.mobile.MobileHardwareTransport

actual fun securityKeysSupported(): Boolean = false

actual fun newSecurityKeyTransport(): MobileHardwareTransport =
    error("Security keys arrive with the iOS host app")
