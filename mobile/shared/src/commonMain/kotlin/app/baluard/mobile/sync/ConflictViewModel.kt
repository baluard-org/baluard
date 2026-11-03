package app.baluard.mobile.sync

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import app.baluard.mobile.MobileVaultInterface

/**
 * State holder for the conflict resolution panel (B4). One decision at a
 * time: the runtime surfaces the head pending conflict; resolving it drains
 * the queue and the next poll shows the following one.
 *
 * Refresh triggers live in `App.kt` (after each sync event + a 15s poll
 * while unlocked); a failed refresh keeps the previous state so a transient
 * FFI error never blanks a decision the user is mid-way through.
 */
class ConflictViewModel {
    /** Head conflict awaiting a verdict; null = nothing to show. */
    var current by mutableStateOf<PendingConflictDto?>(null)
        private set

    /** Total conflicts still queued (including [current]); drives the badge. */
    var queued by mutableIntStateOf(0)
        private set

    /** True while a verdict is being applied (buttons disabled). */
    var resolving by mutableStateOf(false)
        private set

    /** Non-null when the last verdict failed; the panel shows a retry hint. */
    var error by mutableStateOf<String?>(null)
        private set

    /** Poll the head pending conflict. Cheap local FFI call. */
    suspend fun refresh(vault: MobileVaultInterface) {
        if (resolving) return
        val dto = parsePendingConflict(
            runCatching { vault.getPendingConflictDetails() }.getOrElse { return },
        )
        current = dto?.takeIf { it.pending && !it.autoMerged }
        queued = dto?.count ?: 0
    }

    /** Drop everything (vault locked / switching). */
    fun clear() {
        current = null
        queued = 0
        error = null
    }

    /**
     * Apply a verdict. Returns false when the FFI call failed (the conflict
     * STAYS queued so the user can retry or pick another verdict).
     */
    suspend fun resolve(vault: MobileVaultInterface, verdict: ConflictVerdict): Boolean {
        resolving = true
        error = null
        val ok = runCatching { vault.resolveConflict(verdict.wire) }.isSuccess
        if (!ok) error = "resolve_failed"
        // Clear the guard BEFORE the refresh: resolve's own poll must not be
        // swallowed, or a drained queue leaves a stale panel on screen.
        resolving = false
        refresh(vault)
        return ok
    }
}
