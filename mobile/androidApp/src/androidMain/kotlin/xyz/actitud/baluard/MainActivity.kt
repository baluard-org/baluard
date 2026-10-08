package xyz.actitud.baluard

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import xyz.actitud.baluard.autofill.AutofillSaveToken
import xyz.actitud.baluard.platform.AppContextHolder
import xyz.actitud.baluard.platform.AutofillSavePrefill
import xyz.actitud.baluard.ui.App
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId

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

    @OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // M4: app-wide FLAG_SECURE — screenshots, recents preview, and
        // unprivileged screen recording stay blank for the whole app, not
        // per-screen. Compose UIs render before per-screen effects run, so
        // the flag must be set before first frame. Strictly user-setting
        // driven (default off, fail secure). The only exemption is the E2E
        // gate above (-Pbaluard.e2e), keeping the Settings toggle testable
        // on debug builds.
        AppContextHolder.set(this)
        // E2E builds (-Pbaluard.e2e) skip the flag so Maestro screenshots
        // are not black (E12); no other build type sets BALUARD_E2E.
        if (!BuildConfig.BALUARD_E2E &&
            !xyz.actitud.baluard.platform.ScreenshotPrefs().allowScreenshots()
        ) {
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
            // testTagsAsResourceId exposes Modifier.testTag values as
            // resource-id semantics so Maestro id: selectors resolve
            // (docs/e2e-testing.md Phase 2). Android-only surface.
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .semantics { testTagsAsResourceId = true },
            ) {
                App(
                    savePrefill = autofillSavePrefill,
                    onSavePrefillConsumed = { autofillSavePrefill = null },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        autofillSavePrefill = extractAutofillSave(intent)
    }

    private fun extractAutofillSave(intent: Intent?): AutofillSavePrefill? {
        // Spoof guard (peer-review finding #3, revision): MainActivity is
        // exported (launcher), so any app could start it with save extras.
        // getLaunchedFromPackage is API 34+ (would crash on our minSdk 32),
        // so the guard is a one-time token: the :autofill service process
        // writes a random token to app-sandbox storage right before launch
        // and passes it in the intent. Other apps can neither read the
        // sandbox file nor guess the UUID; the token is consumed on use.
        val token = intent?.getStringExtra(EXTRA_SAVE_TOKEN) ?: return null
        if (!AutofillSaveToken.consume(token)) return null
        val username = intent.getStringExtra(EXTRA_SAVE_USERNAME)
        val password = intent.getStringExtra(EXTRA_SAVE_PASSWORD)
        val uri = intent.getStringExtra(EXTRA_SAVE_URI)
        if (username == null && password == null && uri == null) return null
        return AutofillSavePrefill(username, password, uri)
    }

    companion object {
        const val EXTRA_SAVE_TOKEN = "baluard.autofill.SAVE_TOKEN"
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
