package xyz.actitud.baluard

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import xyz.actitud.baluard.ui.App
import xyz.actitud.baluard.platform.AppContextHolder

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AppContextHolder.set(this)
        enableEdgeToEdge()
        setContent { App() }
    }
}
