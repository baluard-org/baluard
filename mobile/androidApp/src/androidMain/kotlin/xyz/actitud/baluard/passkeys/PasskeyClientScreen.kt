package xyz.actitud.baluard.passkeys

// E2E-only Credential Manager client (plan §12 loopback affordance). Chrome
// on the emulator images routes WebAuthn through Google Password Manager in
// parallel mode, which wins the race before the platform consults third-party
// providers; this screen drives the same androidx.credentials client surface
// deterministically. Reachable only when BALUARD_E2E is set and MainActivity
// is launched with the passkey_client extra — never in release builds. Plain
// views: the androidApp module carries no material3 dependency.

import android.app.Activity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.launch

private const val RP_ID = "localhost"

private const val CREATE_JSON = """{
  "rp": {"id": "localhost", "name": "Passkey E2E"},
  "user": {"id": "ZTJlLXVzZXI", "name": "e2e@localhost", "displayName": "E2E User"},
  "challenge": "Y2hhbGxlbmdlLWNocm9tZQ",
  "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
  "authenticatorSelection": {"residentKey": "required", "userVerification": "required"}
}"""

private const val GET_JSON = """{
  "rpId": "localhost",
  "challenge": "Z2V0LWNoYWxsZW5nZQ",
  "userVerification": "required"
}"""

class PasskeyClientActivity : Activity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        install(this)
    }

    companion object {
        fun install(activity: Activity) {
        val ctx = activity
        val pad = (16 * ctx.resources.displayMetrics.density).toInt()
        val root = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            // Edge-to-edge default draws the first button under the status
            // bar band where taps are consumed by system UI.
            fitsSystemWindows = true
            setPadding(pad, pad, pad, pad)
        }
        val status = TextView(ctx).apply {
            text = "ready"
            // Maestro's accessibility snapshot misses programmatic setText on
            // this node; mirror it into contentDescription so harness
            // selectors can match the ceremony result.
            contentDescription = "ready"
        }
        val create = Button(ctx).apply { text = "Create passkey" }
        val get = Button(ctx).apply { text = "Sign in with passkey" }
        root.addView(
            create,
            ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        root.addView(
            get,
            ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT),
        )
        root.addView(status)
        activity.setContentView(root)

        val scope = kotlinx.coroutines.CoroutineScope(
            kotlinx.coroutines.Dispatchers.Main.immediate +
                kotlinx.coroutines.SupervisorJob(),
        )

        create.setOnClickListener {
            status.text = "creating…"
            status.contentDescription = "creating…"
            val handler = CoroutineExceptionHandler { _, e ->
                status.text = "CREATE FAIL ${e.javaClass.simpleName}: ${e.message?.take(140)}"
            status.contentDescription = "CREATE FAIL ${e.javaClass.simpleName}: ${e.message?.take(140)}"
            }
            scope.launch(handler) {
                val manager = CredentialManager.create(ctx)
                val response = manager.createCredential(
                    ctx,
                    CreatePublicKeyCredentialRequest(CREATE_JSON),
                )
                status.text = "CREATE OK $response"
            status.contentDescription = "CREATE OK $response"
            }
        }
        get.setOnClickListener {
            status.text = "signing…"
            status.contentDescription = "signing…"
            val handler = CoroutineExceptionHandler { _, e ->
                status.text = "GET FAIL ${e.javaClass.simpleName}: ${e.message?.take(140)}"
            status.contentDescription = "GET FAIL ${e.javaClass.simpleName}: ${e.message?.take(140)}"
            }
            scope.launch(handler) {
                val manager = CredentialManager.create(ctx)
                val response = manager.getCredential(
                    ctx,
                    GetCredentialRequest(listOf(GetPublicKeyCredentialOption(GET_JSON))),
                )
                val cred = response.credential
                check(cred is PublicKeyCredential) { "unexpected credential type" }
                status.text = "GET OK ${cred.authenticationResponseJson.take(200)}"
            status.contentDescription = "GET OK ${cred.authenticationResponseJson.take(200)}"
            }
        }
    }
    }
}
