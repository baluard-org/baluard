package app.baluard.mobile.platform

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The auth PendingIntents (unlock ceremony, lockedVaultDataset,
 * openBaluardDataset) MUST stay mutable: the framework only attaches
 * EXTRA_ASSIST_STRUCTURE through fillIn, which immutable PendingIntents
 * skip. A silent regression to FLAG_IMMUTABLE would fall back to pinned
 * field ids and still pass every behavioural test. Source-level guard,
 * same style as AutofillProcessIsolationTest.
 */
class AuthPendingIntentMutabilityTest {

    @Test
    fun authPendingIntentsStayMutable() {
        val source = findBuilder().readText()
        val mutable = "FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT"
        val immutable = "FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT"
        assertEquals(3, source.split(mutable).size - 1, "auth PendingIntents must be FLAG_MUTABLE")
        assertEquals(
            1,
            source.split(immutable).size - 1,
            "exactly one immutable PendingIntent allowed: the inline-chip MainActivity launch",
        )
    }

    /** Walk up from the test working dir to the repo root, then into androidApp. */
    private fun findBuilder(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".")
        repeat(6) {
            val d = dir ?: return@repeat
            val candidate = File(
                d,
                "mobile/androidApp/src/androidMain/kotlin/app/baluard/mobile/autofill/AutofillResponseBuilder.kt",
            )
            if (candidate.isFile) return candidate
            dir = d.parentFile
        }
        error("AutofillResponseBuilder.kt not found from ${System.getProperty("user.dir")}")
    }
}
