package xyz.actitud.baluard.sync

import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.TimeSource

/** Sync button feedback phases (desktop AutoSyncIndicator parity). */
enum class SyncPhase { Idle, Syncing, Synced, Offline }

private val MIN_SPIN = 600.milliseconds
private val RESULT_BEAT = 2500.milliseconds

/**
 * Pull now with the shared spinner choreography: guarantee a visible spin
 * (fast LAN syncs would flash for one frame), report the outcome, then
 * settle back to idle. [afterPull] refreshes whatever the caller needs
 * (conflicts, list, settings status); [onResult] fires after the terminal
 * beat is set (toasts land there) and before the settle.
 */
suspend fun runSyncCycle(
    doPull: suspend () -> Unit,
    afterPull: suspend () -> Unit = {},
    setPhase: (SyncPhase) -> Unit,
    onResult: (Boolean) -> Unit = {},
): Boolean {
    setPhase(SyncPhase.Syncing)
    val mark = TimeSource.Monotonic.markNow()
    val ok = runCatching { doPull() }.isSuccess
    runCatching { afterPull() }
    val hold = MIN_SPIN - mark.elapsedNow()
    if (hold.isPositive()) delay(hold)
    setPhase(if (ok) SyncPhase.Synced else SyncPhase.Offline)
    onResult(ok)
    delay(RESULT_BEAT)
    setPhase(SyncPhase.Idle)
    return ok
}
