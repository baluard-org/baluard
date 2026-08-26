package xyz.actitud.baluard.platform

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * M8: the manifest comment promised a separate autofill process while the
 * attribute was missing. Source-level assertion so the promise cannot rot
 * again: by the time the KEK-gated credential path lands in the service, it
 * MUST already run outside the main process.
 */
class AutofillProcessIsolationTest {

    @Test
    fun autofillServiceRunsInItsOwnProcess() {
        val manifest = findManifest().readText()
        val serviceBlock = manifest.substringAfter("<service", "")
            .substringBefore("</service>")
        assertTrue(serviceBlock.contains("BaluardAutofillService"), "autofill service block not found")
        assertTrue(
            serviceBlock.contains("android:process=\":autofill\""),
            "BaluardAutofillService must declare android:process=\":autofill\" (M8): the KEK-gated " +
                "credential path must never run in the main process",
        )
    }

    /** Walk up from the test working dir to the repo root, then into androidApp. */
    private fun findManifest(): File {
        var dir: File? = File(System.getProperty("user.dir") ?: ".")
        repeat(6) {
            val d = dir ?: return@repeat
            val candidate = File(d, "mobile/androidApp/src/androidMain/AndroidManifest.xml")
            if (candidate.isFile) return candidate
            dir = d.parentFile
        }
        error("androidApp AndroidManifest.xml not found from ${System.getProperty("user.dir")}")
    }
}
