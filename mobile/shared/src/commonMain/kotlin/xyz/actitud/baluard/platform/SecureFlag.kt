package xyz.actitud.baluard.platform

/**
 * Screenshots / screen-recording shield for secret-bearing screens (plan §3.5:
 * recompose-based screenshot capture is the real risk on a managed heap).
 * `true` on enter, `false` on leave.
 */
expect fun setSecureFlag(enabled: Boolean)
