package xyz.actitud.baluard.platform

/**
 * iOS `actual`: no-op for now. The iOS slice wires the equivalent
 * (UITextField secure-entry / screen-capture prevention) when the host
 * platform lands.
 */
actual fun setSecureFlag(enabled: Boolean) {
    // No iOS equivalent wired yet.
}
