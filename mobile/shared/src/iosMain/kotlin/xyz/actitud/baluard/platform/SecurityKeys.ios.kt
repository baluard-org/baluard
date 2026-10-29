package xyz.actitud.baluard.platform

import xyz.actitud.baluard.MobileHardwareTransport

actual fun securityKeysSupported(): Boolean = false

actual fun newSecurityKeyTransport(): MobileHardwareTransport =
    error("Security keys arrive with the iOS host app")
