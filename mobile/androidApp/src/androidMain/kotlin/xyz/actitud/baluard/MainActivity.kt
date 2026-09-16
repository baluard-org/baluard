package xyz.actitud.baluard

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import xyz.actitud.baluard.platform.AppContextHolder
import xyz.actitud.baluard.platform.AutofillSavePrefill
import xyz.actitud.baluard.ui.App

/**
 * FragmentActivity (not plain ComponentActivity): BiometricPrompt's
 * CryptoObject ceremony needs a FragmentActivity host (B5 quick unlock).
 *
 * launchMode="singleTask": autofill save prompts (Phase 6 P4) land here as
 * onNewIntent instead of stacking duplicate app instances.
 */
class MainActivity : FragmentActivity() {

    /** Captured login from the autofill save prompt, until the editor seeds. */
    private var autofillSavePrefill by mutableStateOf<AutofillSavePrefill?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // M4: app-wide FLAG_SECURE — screenshots, recents preview, and
        // unprivileged screen recording stay blank for the whole app, not
        // per-screen. Compose UIs render before per-screen effects run, so
        // the flag must be set before first frame. Strictly user-setting
        // driven (default off, fail secure) — no build-type exemption, so
        // the Settings toggle is fully testable on debug builds too.
        AppContextHolder.set(this)
        if (!xyz.actitud.baluard.platform.ScreenshotPrefs().allowScreenshots()) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        AppContextHolder.setActivity(this)
        // M3: install the Keystore-wrapped provider-token encryption key
        // before any provider flow can run.
        xyz.actitud.baluard.platform.TokenEncryption.install(this)
        enableEdgeToEdge()
        // Cold start with a save handoff; recreation (rotation, process
        // death) must NOT re-seed a form the user already dismissed.
        if (savedInstanceState == null) {
            autofillSavePrefill = extractAutofillSave(intent)
        }
        setContent {
            App(
                savePrefill = autofillSavePrefill,
                onSavePrefillConsumed = { autofillSavePrefill = null },
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        autofillSavePrefill = extractAutofillSave(intent)
    }

    private fun extractAutofillSave(intent: Intent?): AutofillSavePrefill? {
        // Spoof guard (peer-review finding #3): MainActivity is exported
        // (launcher), so any app could start it with save extras. Only trust
        // them when the launch came from our own package (the :autofill
        // service process). Strict: null attribution (system launches) is
        // rejected too; those never carry our extras.
        if (getLaunchedFromPackage() != packageName) return null
        val username = intent?.getStringExtra(EXTRA_SAVE_USERNAME)
        val password = intent?.getStringExtra(EXTRA_SAVE_PASSWORD)
        val uri = intent?.getStringExtra(EXTRA_SAVE_URI)
        if (username == null && password == null && uri == null) return null
        return AutofillSavePrefill(username, password, uri)
    }

    companion object {
        const val EXTRA_SAVE_USERNAME = "baluard.autofill.SAVE_USERNAME"
        const val EXTRA_SAVE_PASSWORD = "baluard.autofill.SAVE_PASSWORD"
        const val EXTRA_SAVE_URI = "baluard.autofill.SAVE_URI"
    }

    override fun onPause() {
        super.onPause()
        xyz.actitud.baluard.platform.AppBackground.pause()
    }

    override fun onResume() {
        super.onResume()
        xyz.actitud.baluard.platform.AppBackground.resume()
    }

    override fun onDestroy() {
        AppContextHolder.clearActivity(this)
        super.onDestroy()
    }
}
