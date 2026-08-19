package xyz.actitud.baluard.sync

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** B4: view-model behavior over the FFI stub. */
class ConflictViewModelTest {

    @Test
    fun refreshSurfacesPendingConflict() = runTest {
        val vm = ConflictViewModel()
        val vault = StubVault(
            pendingConflictJson = """{"pending":true,"cross_epoch":false,"count":2,
                "cipher_id":"id1","name":"GitHub","cipher_type":"login",
                "fields":[{"key":"password","label":"password","sensitive":true}]}""",
        )
        vm.refresh(vault)
        assertEquals("GitHub", vm.current?.name)
        assertEquals(2, vm.queued)
    }

    @Test
    fun refreshHidesAutoMergedAndNothingPending() = runTest {
        val vm = ConflictViewModel()
        vm.refresh(StubVault("""{"pending":true,"auto_merged":true,"push_pending":false}"""))
        assertNull(vm.current)

        vm.refresh(StubVault("""{"pending":false}"""))
        assertNull(vm.current)
    }

    @Test
    fun refreshKeepsPriorStateOnFfiError() = runTest {
        val vm = ConflictViewModel()
        vm.refresh(
            StubVault(
                pendingConflictJson = """{"pending":true,"cross_epoch":false,"count":1,
                    "cipher_id":"id1","name":"Keep","cipher_type":"login","fields":[]}""",
            ),
        )
        // A vault whose FFI call throws: the user stays mid-decision.
        val broken = object : StubVault() {
            override suspend fun getPendingConflictDetails(): String =
                throw IllegalStateException("ffi down")
        }
        vm.refresh(broken)
        assertEquals("Keep", vm.current?.name)
    }

    @Test
    fun resolveAppliesVerdictAndRefreshes() = runTest {
        val vm = ConflictViewModel()
        val vault = StubVault(
            pendingConflictJson = """{"pending":true,"cross_epoch":false,"count":1,
                "cipher_id":"id1","name":"A","cipher_type":"login","fields":[]}""",
        )
        vm.refresh(vault)
        val ok = vm.resolve(vault, ConflictVerdict.KEEP_LOCAL)
        assertTrue(ok)
        assertEquals("resolveConflict:keep_local", vault.calls.last { it.startsWith("resolveConflict") })
        // resolve triggers a refresh; the stub still reports the conflict, but
        // the important part is the call sequence: verdict then poll.
        assertEquals(
            listOf("getPendingConflictDetails", "resolveConflict:keep_local", "getPendingConflictDetails"),
            vault.calls.filter { it != "shouldAutoLock" },
        )
    }

    @Test
    fun failedResolveStaysQueuedWithError() = runTest {
        val vm = ConflictViewModel()
        val vault = object : StubVault(
            pendingConflictJson = """{"pending":true,"cross_epoch":false,"count":1,
                "cipher_id":"id1","name":"A","cipher_type":"login","fields":[]}""",
        ) {
            override suspend fun resolveConflict(verdict: String): String =
                throw RuntimeException("push failed")
        }
        vm.refresh(vault)
        val ok = vm.resolve(vault, ConflictVerdict.KEEP_REMOTE)
        assertFalse(ok)
        assertEquals("resolve_failed", vm.error)
        // The conflict stays for retry.
        assertEquals("A", vm.current?.name)
    }

    @Test
    fun clearDropsEverything() = runTest {
        val vm = ConflictViewModel()
        vm.refresh(
            StubVault(
                pendingConflictJson = """{"pending":true,"cross_epoch":false,"count":3,
                    "cipher_id":"id1","name":"A","cipher_type":"login","fields":[]}""",
            ),
        )
        vm.clear()
        assertNull(vm.current)
        assertEquals(0, vm.queued)
        assertNull(vm.error)
    }
}
