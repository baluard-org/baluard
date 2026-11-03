package app.baluard.mobile.auth

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

/**
 * LRU + lifecycle bookkeeping for the mobile multi-Space session
 * (ADR 0087 S4-9). Fakes the vault handles; the production adapter
 * wraps the uniffi MobileVault and is a three-line delegation.
 */
class MultiVaultSessionTest {

    /** Fake handle with programmable lock state and timer. */
    private class FakeVault(
        override val mobile: app.baluard.mobile.MobileVault? = null,
    ) : SessionVault {
        var unlocked = true
        var expired = false
        var lockCount = 0

        override suspend fun isUnlocked(): Boolean = unlocked
        override suspend fun shouldAutoLock(): Boolean = expired
        override suspend fun lock() {
            unlocked = false
            lockCount++
        }
    }

    @Test
    fun boundEvictsLocksTheEvictedVault() = runTest {
        val session = MultiVaultSession(max = 2)
        val a = FakeVault()
        val b = FakeVault()
        val c = FakeVault()
        session.adopt("/a", a, kek = null)
        session.adopt("/b", b, kek = null)
        session.adopt("/c", c, kek = null)
        // Size 3 > max 2: /a is the LRU victim. Eviction LOCKS it — no
        // background walker exists on mobile, so a dropped unlocked handle
        // would hold its keys until process end.
        assertEquals(1, a.lockCount, "evicted vault must be locked, not dropped")
        assertFalse(a.unlocked)
        assertFalse(session.holds("/a"), "evicted slot must be gone")
        assertTrue(session.holds("/b"))
        assertTrue(session.holds("/c"))
        // Adopting over a live path locks the superseded handle too.
        session.adopt("/c", FakeVault(), kek = null)
        assertEquals(1, c.lockCount)
    }

    @Test
    fun switchToFastPathAdoptsWithoutUnlockAndKeepsOthers() = runTest {
        val session = MultiVaultSession(max = 3)
        val a = FakeVault()
        val b = FakeVault()
        session.adopt("/a", a, kek = null)
        session.adopt("/b", b, kek = null)
        assertTrue(session.switchTo("/a"), "cached unlocked vault fast-paths")
        assertEquals(a, session.active(), "fast path makes the target active")
        assertTrue(a.unlocked, "fast path must not touch the vault")
        assertTrue(session.holds("/b"), "other sessions survive a switch")
    }

    @Test
    fun staleCachedVaultDropsAndFallsBackToUnlock() = runTest {
        val session = MultiVaultSession(max = 3)
        val a = FakeVault()
        val kek = ByteArray(32) { 1 }
        session.adopt("/a", a, kek = kek)
        a.unlocked = false // auto-locked itself while cached
        assertFalse(session.switchTo("/a"), "locked cached vault must not fast-path")
        assertFalse(session.holds("/a"), "dead entry is dropped")
        assertNull(session.active(), "nothing else was held")
        assertTrue(kek.all { it == 0.toByte() }, "the stale entry's KEK is wiped")
    }

    @Test
    fun lockActiveAndLockAllLockEverySession() = runTest {
        val session = MultiVaultSession(max = 3)
        val a = FakeVault()
        val b = FakeVault()
        session.adopt("/a", a, kek = null)
        session.adopt("/b", b, kek = null)
        assertTrue(session.lockActive())
        assertEquals(1, b.lockCount, "active is the last-touched entry")
        assertTrue(a.unlocked, "lockActive spares the others")
        // lockActive freed /b's slot, so lockAll now sweeps the remaining /a.
        assertEquals(1, session.lockAll())
        assertFalse(a.unlocked)
        assertFalse(b.unlocked)
        assertNull(session.active(), "locking frees every slot")
    }

    @Test
    fun forgetLocksAndFreesExactlyOneSlot() = runTest {
        val session = MultiVaultSession(max = 3)
        val a = FakeVault()
        val b = FakeVault()
        session.adopt("/a", a, kek = null)
        session.adopt("/b", b, kek = null)
        session.forget("/a")
        assertFalse(a.unlocked)
        assertTrue(b.unlocked)
        assertEquals(b, session.active())
        assertFalse(session.holds("/a"), "forgotten slot is gone")
    }

    @Test
    fun lockInactiveSparesOnlyTheActiveVault() = runTest {
        val session = MultiVaultSession(max = 3)
        val a = FakeVault()
        val b = FakeVault()
        val c = FakeVault()
        session.adopt("/a", a, kek = null)
        session.adopt("/b", b, kek = null)
        session.adopt("/c", c, kek = null)
        assertEquals(2, session.lockInactive())
        assertTrue(c.unlocked, "the active vault is spared")
        assertFalse(a.unlocked)
        assertFalse(b.unlocked)
        assertEquals(c, session.active())
        // A background pass with one active + one inactive session locks the
        // inactive one only (earlier passes already freed their slots).
        session.adopt("/d", FakeVault(), kek = null)
        assertEquals(1, session.lockInactive())
    }

    @Test
    fun enforceAutoLockLocksOnlyExpiredSessions() = runTest {
        val session = MultiVaultSession(max = 3)
        val a = FakeVault()
        val b = FakeVault()
        val c = FakeVault()
        session.adopt("/a", a, kek = null)
        session.adopt("/b", b, kek = null)
        session.adopt("/c", c, kek = null)
        b.expired = true // cached vault whose timer ran out
        assertEquals(1, session.enforceAutoLock())
        assertTrue(b.lockCount == 1 && !b.unlocked, "the expired session locks")
        assertTrue(c.unlocked, "the active vault is governed by its own poll")
        assertTrue(a.unlocked, "unexpired sessions stay")
        assertFalse(session.holds("/b"), "the locked slot is freed")
    }
}
