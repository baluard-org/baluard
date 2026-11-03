package app.baluard.mobile

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.credentials.CreatePublicKeyCredentialResponse
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.provider.PendingIntentHandler
import app.baluard.mobile.autofill.AutofillSaveToken
import app.baluard.mobile.passkeys.OriginValidator
import app.baluard.mobile.passkeys.PasskeyRequest
import app.baluard.mobile.passkeys.PasskeyRequestManager
import app.baluard.mobile.passkeys.PasskeyUiRequest
import app.baluard.mobile.passkeys.UnlockReturnLeg
import app.baluard.mobile.platform.AppContextHolder
import app.baluard.mobile.platform.AutofillSavePrefill
import app.baluard.mobile.ui.App
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

    /**
     * Staged passkey provider request (G10): re-read from the intent and
     * proven ours via [PasskeyRequestManager] — intent extras alone are
     * never authority (§11).
     */
    private var passkeyRequest by mutableStateOf<PasskeyUiRequest?>(null)

    private val originValidator by lazy { OriginValidator(this) }

    // Fulfillment legs are short one-shot IO on the main-process session.
    private val passkeyScope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.Dispatchers.Main.immediate +
            kotlinx.coroutines.SupervisorJob(),
    )

    private fun extractPasskeyRequest(intent: Intent?): PasskeyUiRequest? {
        val id = intent?.getStringExtra(
            app.baluard.mobile.passkeys.BaluardCredentialProviderService.EXTRA_REQUEST_ID,
        ) ?: return null
        return when (val staged = PasskeyRequestManager.peek(id)) {
            is PasskeyRequest.Create -> PasskeyUiRequest.Create(
                id = staged.id,
                requestJson = staged.requestJson,
                rpId = staged.rpId,
                rpName = staged.rpName,
                userName = staged.userName,
                origin = staged.origin,
                clientDataHash = staged.clientDataHash,
            )

            is PasskeyRequest.Assert -> PasskeyUiRequest.Assert(
                id = staged.id,
                requestJson = staged.requestJson,
                rpId = staged.rpId,
                origin = staged.origin,
                clientDataHash = staged.clientDataHash,
                credentialId = staged.credentialId,
                allowCredentialIds = staged.allowCredentialIds,
            )

            is PasskeyRequest.Unlock -> PasskeyUiRequest.Unlock(id = staged.id)
            null -> null
        }
    }

    private fun completePasskey(resultJson: String) {
        val request = passkeyRequest ?: return
        val result = Intent()
        when (request) {
            is PasskeyUiRequest.Create -> PendingIntentHandler.setCreateCredentialResponse(
                result,
                CreatePublicKeyCredentialResponse(resultJson),
            )

            is PasskeyUiRequest.Assert -> PendingIntentHandler.setGetCredentialResponse(
                result,
                GetCredentialResponse(PublicKeyCredential(resultJson)),
            )

            is PasskeyUiRequest.Unlock -> return
        }
        PasskeyRequestManager.consume(request.id)
        passkeyRequest = null
        setResult(RESULT_OK, result)
        finish()
    }

    private fun cancelPasskey() {
        val request = passkeyRequest ?: return
        val result = Intent()
        when (request) {
            is PasskeyUiRequest.Create -> PendingIntentHandler.setCreateCredentialException(
                result,
                CreateCredentialCancellationException(),
            )

            is PasskeyUiRequest.Assert -> PendingIntentHandler.setGetCredentialException(
                result,
                GetCredentialCancellationException(),
            )

            is PasskeyUiRequest.Unlock -> return
        }
        PasskeyRequestManager.consume(request.id)
        passkeyRequest = null
        setResult(RESULT_OK, result)
        finish()
    }

    private fun completePasskeyUnlock() {
        val request = passkeyRequest as? PasskeyUiRequest.Unlock ?: return
        PasskeyRequestManager.consume(request.id)
        passkeyRequest = null
        passkeyScope.launch {
            val answered = UnlockReturnLeg.answer(this@MainActivity, originValidator)
            if (!answered) setResult(RESULT_CANCELED)
            finish()
        }
    }

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
            !app.baluard.mobile.platform.ScreenshotPrefs().allowScreenshots()
        ) {
            window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        }
        AppContextHolder.setActivity(this)
        // M3: install the Keystore-wrapped provider-token encryption key
        // before any provider flow can run.
        app.baluard.mobile.platform.TokenEncryption.install(this)
        enableEdgeToEdge()
        // Cold start with a save handoff; recreation (rotation, process
        // death) must NOT re-seed a form the user already dismissed.
        if (savedInstanceState == null) {
            autofillSavePrefill = extractAutofillSave(intent)
            passkeyRequest = extractPasskeyRequest(intent)
            if (BuildConfig.BALUARD_E2E) {
                android.util.Log.e(
                    "PasskeyMain",
                    "onCreate extract=${passkeyRequest?.javaClass?.simpleName} action=${intent?.action}",
                )
            }
        } else if (intent?.getStringExtra(
                app.baluard.mobile.passkeys.BaluardCredentialProviderService.EXTRA_REQUEST_ID,
            ) != null && passkeyRequest == null && extractPasskeyRequest(intent) == null
        ) {
            // Recreation after process death: the in-memory manager died with
            // it, so the staged request is unrecoverable — close the sheet
            // cleanly instead of hanging it (agy BLOCKER-followup). The extract above rules out
            // config-change recreation, where the manager still holds the request.
            val result = Intent()
            if (intent.action == app.baluard.mobile.passkeys.BaluardCredentialProviderService.ACTION_CREATE_PASSKEY) {
                PendingIntentHandler.setCreateCredentialException(
                    result,
                    androidx.credentials.exceptions.CreateCredentialNoCreateOptionException(),
                )
            } else {
                PendingIntentHandler.setGetCredentialException(
                    result,
                    androidx.credentials.exceptions.NoCredentialException(),
                )
            }
            setResult(RESULT_OK, result)
            finish()
            return
        }
        setContent {
            // testTagsAsResourceId exposes Modifier.testTag values as
            // resource-id semantics so Maestro id: selectors resolve
            // (Phase 2). Android-only surface.
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .semantics { testTagsAsResourceId = true },
            ) {
                App(
                    savePrefill = autofillSavePrefill,
                    onSavePrefillConsumed = { autofillSavePrefill = null },
                    passkeyRequest = passkeyRequest,
                    onPasskeyResult = { completePasskey(it) },
                    onPasskeyCancel = { cancelPasskey() },
                    onPasskeyUnlockComplete = { completePasskeyUnlock() },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        extractAutofillSave(intent)?.let { autofillSavePrefill = it }
        extractPasskeyRequest(intent)?.let { passkeyRequest = it }
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
        // Credentials travel in the consumed sandbox token file; the
        // intent extras carry the random token alone.
        return AutofillSaveToken.consume(token)
    }

    companion object {
        const val EXTRA_SAVE_TOKEN = "baluard.autofill.SAVE_TOKEN"
    }

    override fun onPause() {
        super.onPause()
        app.baluard.mobile.platform.AppBackground.pause()
    }

    override fun onResume() {
        super.onResume()
        app.baluard.mobile.platform.AppBackground.resume()
    }

    override fun onDestroy() {
        passkeyScope.cancel()
        AppContextHolder.clearActivity(this)
        super.onDestroy()
    }
}
