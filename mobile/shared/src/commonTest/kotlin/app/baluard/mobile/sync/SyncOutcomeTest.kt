package app.baluard.mobile.sync

import app.baluard.mobile.ui.toast.Toast
import app.baluard.mobile.ui.toast.ToastEntry
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the tag -> toast matrix against the Rust PullReport tags, and the
 * Synced/Offline/none phase classes of runSyncCycle. The toast function
 * takes the translator as a parameter, so the identity function makes the
 * toast message itself the i18n key under test.
 */
class SyncOutcomeTest {

    private fun lastToast(): ToastEntry? = Toast.entries.lastOrNull()

    private fun assertToast(tag: String?, type: String, key: String) {
        val before = Toast.entries.size
        syncOutcomeToast(tag) { it }
        val entry = lastToast()
        assertEquals(before + 1, Toast.entries.size, "tag $tag produced no toast")
        assertEquals(type, entry!!.type, "tag $tag wrong toast type")
        assertEquals(key, entry.message, "tag $tag wrong copy key")
    }

    @Test
    fun every_report_tag_maps_to_its_own_copy() {
        assertToast("pulled", "success", "sync.synced")
        assertToast("up_to_date", "info", "sync.upToDate")
        assertToast("kept_local", "info", "sync.keptLocal")
        assertToast("idle", "info", "sync.noRemote")
        assertToast("paused", "info", "sync.blocked")
        assertToast("busy", "info", "sync.blocked")
        assertToast("skipped", "info", "sync.blocked")
        assertToast("offline", "error", "sync.offline")
        assertToast("access_denied", "error", "sync.denied")
        assertToast("error", "error", "sync.error")
    }

    @Test
    fun null_transport_throws_report_offline() {
        assertToast(null, "error", "sync.offline")
    }

    @Test
    fun unknown_tags_stay_silent() {
        val before = Toast.entries.size
        syncOutcomeToast("locked") { it }
        syncOutcomeToast("something-new") { it }
        assertEquals(before, Toast.entries.size, "silent tags produced toasts")
    }

    @Test
    fun phase_classes_success_failure_and_did_not_run() = runTest {
        suspend fun phases(tag: String?): List<String> {
            val seen = mutableListOf<String>()
            runSyncCycle(
                doPull = { tag },
                setPhase = { seen.add(it.name) },
            )
            return seen
        }

        // Success: Synced flash, then settle.
        assertTrue(phases("pulled") == listOf("Syncing", "Synced", "Idle"))
        assertTrue(phases("up_to_date") == listOf("Syncing", "Synced", "Idle"))
        assertTrue(phases("kept_local") == listOf("Syncing", "Synced", "Idle"))
        // Failure: Offline flash.
        assertTrue(phases("offline") == listOf("Syncing", "Offline", "Idle"))
        assertTrue(phases("error") == listOf("Syncing", "Offline", "Idle"))
        assertTrue(phases(null) == listOf("Syncing", "Offline", "Idle"))
        // Did not run: no failure flash, straight back to Idle.
        assertTrue(phases("idle") == listOf("Syncing", "Idle"))
        assertTrue(phases("paused") == listOf("Syncing", "Idle"))
        assertTrue(phases("busy") == listOf("Syncing", "Idle"))
        assertTrue(phases("skipped") == listOf("Syncing", "Idle"))
    }
}
