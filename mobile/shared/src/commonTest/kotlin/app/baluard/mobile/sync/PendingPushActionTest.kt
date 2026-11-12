package app.baluard.mobile.sync

import kotlin.test.Test
import kotlin.test.assertEquals

/** Pins the pending-push watcher's state machine (driven by ui/App.kt's
 * status poll). The runtime returns to Idle after a FAILED cycle without
 * advancing last_sync, so Idle never means success on its own. */
class PendingPushActionTest {

    @Test
    fun dirtyKeepsWatching() {
        assertEquals(PendingPushAction.Keep, pendingPushAction("dirty", false, false, false))
    }

    @Test
    fun syncingKeepsWatching() {
        assertEquals(PendingPushAction.Keep, pendingPushAction("syncing", true, true, false))
    }

    @Test
    fun idleAfterEvidenceFlashesByLastSyncAdvance() {
        assertEquals(PendingPushAction.Success, pendingPushAction("idle", true, false, true))
        assertEquals(PendingPushAction.Failure, pendingPushAction("idle", true, false, false))
        assertEquals(PendingPushAction.Success, pendingPushAction("idle", false, true, true))
        assertEquals(PendingPushAction.Failure, pendingPushAction("idle", false, true, false))
    }

    @Test
    fun idleWithoutEvidenceKeepsWatching() {
        assertEquals(PendingPushAction.Keep, pendingPushAction("idle", false, false, false))
    }

    @Test
    fun offlineAfterQueuedIsFailure() {
        assertEquals(PendingPushAction.Failure, pendingPushAction("offline", true, false, true))
        assertEquals(PendingPushAction.Failure, pendingPushAction("offline", true, false, false))
        // Pre-existing offline with nothing queued: not our push, keep watching.
        assertEquals(PendingPushAction.Keep, pendingPushAction("offline", false, false, false))
    }

    @Test
    fun needsDecisionClears() {
        assertEquals(PendingPushAction.Clear, pendingPushAction("needsdecision", true, false, false))
    }

    @Test
    fun unknownStateKeepsWatching() {
        assertEquals(PendingPushAction.Keep, pendingPushAction("weird", true, true, true))
    }
}
