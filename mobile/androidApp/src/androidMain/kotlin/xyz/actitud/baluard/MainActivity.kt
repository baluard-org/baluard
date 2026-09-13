package xyz.actitud.baluard

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.fragment.app.FragmentActivity
import xyz.actitud.baluard.ui.App
import xyz.actitud.baluard.platform.AppContextHolder

/**
 * FragmentActivity (not plain ComponentActivity): BiometricPrompt's
 * CryptoObject ceremony needs a FragmentActivity host (B5 quick unlock).
 */
class MainActivity : FragmentActivity() {
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
        setContent { App() }
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
