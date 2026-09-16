package xyz.actitud.baluard.autofill

import android.app.Activity
import android.os.Bundle

/**
 * NoDisplay trampoline (Bitwarden's AccessibilityActivity pattern): its ONLY
 * job is to finish instantly, which collapses the quick-settings shade and
 * forces the window transition the armed [BaluardAccessibilityService] acts
 * on. Same :autofill process; nothing else happens here.
 */
class A11yTileTrampoline : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        finish()
    }
}
