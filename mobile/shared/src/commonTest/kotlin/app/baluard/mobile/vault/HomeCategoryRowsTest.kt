package app.baluard.mobile.vault

import kotlin.test.Test
import kotlin.test.assertEquals

class HomeCategoryRowsTest {
    @Test
    fun excludesSshKeyAndCapsAtFourPrimaryCategories() {
        val all = listOf(
            "login" to 10,
            "card" to 2,
            "identity" to 1,
            "securenote" to 3,
            "sshkey" to 4,
            "bankaccount" to 2,
        )
        assertEquals(
            listOf("login" to 10, "card" to 2, "identity" to 1, "securenote" to 3),
            homeCategoryRows(all),
        )
    }

    @Test
    fun sshOnlyVaultLeavesPrimaryRowsEmptySoViewAllStillReachesIt() {
        val all = listOf("sshkey" to 2)
        assertEquals(emptyList(), homeCategoryRows(all))
    }
}
