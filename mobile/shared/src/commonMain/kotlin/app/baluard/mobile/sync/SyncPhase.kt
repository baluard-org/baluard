package app.baluard.mobile.sync

import app.baluard.mobile.ui.toast.Toast
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
    doPull: suspend () -> String?,
    afterPull: suspend () -> Unit = {},
    setPhase: (SyncPhase) -> Unit,
    onResult: (Boolean, String?) -> Unit = { _, _ -> },
): Boolean {
    setPhase(SyncPhase.Syncing)
    val mark = TimeSource.Monotonic.markNow()
    val tag = runCatching { doPull() }.getOrNull()
    val ok = tag == "pulled" || tag == "up_to_date" || tag == "kept_local"
    runCatching { afterPull() }
    val hold = MIN_SPIN - mark.elapsedNow()
    if (hold.isPositive()) delay(hold)
    setPhase(if (ok) SyncPhase.Synced else SyncPhase.Offline)
    onResult(ok, tag)
    delay(RESULT_BEAT)
    setPhase(SyncPhase.Idle)
    return ok
}

/**
 * Toast for the Rust pull report tag (see PullReport). Each outcome gets
 * its own honest copy: pulled/up-to-date/kept-local succeed, idle means no
 * sync is configured, paused/busy/skipped mean the pull did not run, and
 * offline/denied are failures.
 */
fun syncOutcomeToast(tag: String?, t: (String) -> String) {
    when (tag) {
        "pulled" -> Toast.success(t("sync.synced"))
        "up_to_date" -> Toast.info(t("sync.upToDate"))
        "kept_local" -> Toast.info(t("sync.keptLocal"))
        "idle" -> Toast.info(t("sync.noRemote"))
        "paused", "busy", "skipped" -> Toast.info(t("sync.blocked"))
        "offline", null -> Toast.error(t("sync.offline"))
        "access_denied" -> Toast.error(t("sync.denied"))
        else -> Unit
    }
}
