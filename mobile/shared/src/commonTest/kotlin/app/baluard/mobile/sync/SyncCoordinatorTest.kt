package app.baluard.mobile.sync

import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** B3: config gating maps lifecycle events onto the FFI event surface. */
class SyncCoordinatorTest {

    @Test
    fun defaultsCallEveryEvent() = runTest {
        val vault = StubVault()
        val sync = SyncCoordinator(isMeteredNetwork = { false })
        sync.onUnlock(vault)
        sync.onMutation(vault)
        sync.onForeground(vault)
        sync.onBackground(vault)
        sync.pullNow(vault)
        sync.offlineTick(vault)
        assertEquals(
            listOf(
                "syncOnUnlock", "syncOnMutation", "syncOnForeground",
                "syncOnBackground", "syncPullNow", "syncOfflineTick",
            ),
            vault.calls,
        )
    }

    @Test
    fun disabledGatesSkipTheirEvent() = runTest {
        val vault = StubVault()
        val sync = SyncCoordinator(
            SyncConfig(syncOnUnlock = false, syncAfterChange = false, syncOnForeground = false),
            isMeteredNetwork = { false },
        )
        sync.onUnlock(vault)
        sync.onMutation(vault)
        sync.onForeground(vault)
        // onBackground is NOT gated: flushing the debounce on background is
        // mandatory (the OS drops the 5s timer on suspension).
        sync.onBackground(vault)
        assertEquals(listOf("syncOnBackground"), vault.calls)
    }

    @Test
    fun wifiOnlySkipsAutomaticEventsOnMeteredNetwork() = runTest {
        val vault = StubVault()
        val sync = SyncCoordinator(isMeteredNetwork = { true })
        sync.onUnlock(vault)
        sync.onMutation(vault)
        sync.onForeground(vault)
        sync.offlineTick(vault)
        // Explicit gesture + mandatory flush are NOT gated by Wi-Fi-only.
        sync.pullNow(vault)
        sync.onBackground(vault)
        assertEquals(listOf("syncPullNow", "syncOnBackground"), vault.calls)
    }

    @Test
    fun statusProxiesVault() = runTest {
        val vault = StubVault()
        val status = SyncCoordinator(isMeteredNetwork = { false }).status(vault)
        assertTrue(status.active)
        assertEquals("idle", status.state)
    }
}
