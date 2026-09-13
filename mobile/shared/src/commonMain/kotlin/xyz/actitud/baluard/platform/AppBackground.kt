package xyz.actitud.baluard.platform

import xyz.actitud.baluard.totp.Clock

/**
 * App background/foreground transitions, fed by the host activity
 * (Android onPause/onResume). Carries the paused-at timestamp so callers
 * can decide whether an auto-lock timeout elapsed while away.
 */
object AppBackground {
    var pausedAtMs: Long? = null
    var onPause: (() -> Unit)? = null
    var onResume: ((backgroundedMs: Long) -> Unit)? = null

    fun pause() {
        if (pausedAtMs == null) pausedAtMs = Clock.currentTimeMillis()
        onPause?.invoke()
    }

    fun resume() {
        val elapsed = pausedAtMs?.let { Clock.currentTimeMillis() - it }
        pausedAtMs = null
        if (elapsed != null) onResume?.invoke(elapsed)
    }
}
