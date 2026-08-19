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
        AppContextHolder.set(this)
        AppContextHolder.setActivity(this)
        enableEdgeToEdge()
        setContent { App() }
    }

    override fun onDestroy() {
        AppContextHolder.clearActivity(this)
        super.onDestroy()
    }
}
