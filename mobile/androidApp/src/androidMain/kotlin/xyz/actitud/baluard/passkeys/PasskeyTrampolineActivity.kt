package xyz.actitud.baluard.passkeys

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.NoCredentialException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import xyz.actitud.baluard.MainActivity

/**
 * Transparent trampoline (plan §4): re-reads the framework request from the
 * intent (never memory), validates the caller origin (the fulfillment-time
 * gate — Begin validated optimistically), stages the request in
 * [PasskeyRequestManager], launches [MainActivity] for-result, and forwards
 * the result verbatim. The app screens build the responses via
 * [PendingIntentHandler].
 *
 * exported="false": only our own PendingIntents may launch it (§11).
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PasskeyTrampolineActivity : ComponentActivity() {

    private val validator by lazy { OriginValidator(this) }

    private val launcher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        setResult(result.resultCode, result.data)
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) {
            stage(intent)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        stage(intent)
    }

    private val stageScope = kotlinx.coroutines.CoroutineScope(
        kotlinx.coroutines.Dispatchers.Main.immediate +
            kotlinx.coroutines.SupervisorJob(),
    )

    private fun stage(intent: Intent) {
        // The unprivileged-app DAL fetch is real network IO: stage off the
        // main thread (NetworkOnMainThreadException otherwise).
        stageScope.launch {
            val frameworkGet = withContext(kotlinx.coroutines.Dispatchers.IO) {
                runCatching {
                    PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
                        as? ProviderGetCredentialRequest
                }.getOrNull()
            }
            val frameworkBegin = withContext(kotlinx.coroutines.Dispatchers.IO) {
                runCatching {
                    PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
                }.getOrNull()
            }
            val staged = withContext(kotlinx.coroutines.Dispatchers.IO) {
                runCatching { extract(intent) }.getOrNull()
            }
            if (staged == null) {
                failSilently(intent.action)
                return@launch
            }
            PasskeyRequestManager.put(staged.first, frameworkGet, frameworkBegin)
            val appIntent = Intent(this@PasskeyTrampolineActivity, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                putExtra(BaluardCredentialProviderService.EXTRA_REQUEST_ID, staged.first.id)
                action = intent.action
            }
            launcher.launch(appIntent)
        }
    }

    override fun onDestroy() {
        stageScope.cancel()
        super.onDestroy()
    }

    /**
     * Returns the staged request plus the validated ceremony origin; null
     * means refuse (origin or shape) and close silently.
     */
    private fun extract(intent: Intent): Pair<PasskeyRequest, String> {
        val id = java.util.UUID.randomUUID().toString()
        return when (intent.action) {
            BaluardCredentialProviderService.ACTION_CREATE_PASSKEY -> {
                val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
                    as? ProviderCreateCredentialRequest
                    ?: throw IllegalStateException("not a create request")
                val create = request.callingRequest as? CreatePublicKeyCredentialRequest
                    ?: throw IllegalStateException("not a passkey create request")
                val rpId = PasskeyLister.rpIdOf(create.requestJson)
                    ?: throw IllegalStateException("no rp id")
                val origin = originOf(rpId, request.callingAppInfo)
                    ?: throw IllegalStateException("origin refused")
                PasskeyRequest.Create(
                    id = id,
                    requestJson = create.requestJson,
                    rpId = rpId,
                    rpName = rpNameOf(create.requestJson),
                    userName = userNameOf(create.requestJson),
                    clientDataJson = null,
                    clientDataHash = create.clientDataHash?.toB64Url(),
                    origin = origin,
                ) to origin
            }

            BaluardCredentialProviderService.ACTION_GET_PASSKEY -> {
                val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
                    as? ProviderGetCredentialRequest
                    ?: throw IllegalStateException("not a get request")
                val option = request.credentialOptions
                    .filterIsInstance<androidx.credentials.GetPublicKeyCredentialOption>()
                    .firstOrNull()
                    ?: throw IllegalStateException("no passkey option")
                val rpId = PasskeyLister.rpIdOf(option.requestJson)
                    ?: throw IllegalStateException("no rp id")
                val origin = originOf(rpId, request.callingAppInfo)
                    ?: throw IllegalStateException("origin refused")
                PasskeyRequest.Assert(
                    id = id,
                    requestJson = option.requestJson,
                    rpId = rpId,
                    allowCredentialIds = PasskeyLister.allowIdsOf(option.requestJson),
                    clientDataJson = null,
                    clientDataHash = option.clientDataHash?.toB64Url(),
                    origin = origin,
                    credentialId = intent.getStringExtra(
                        BaluardCredentialProviderService.EXTRA_CREDENTIAL_ID,
                    ),
                ) to origin
            }

            BaluardCredentialProviderService.ACTION_UNLOCK_PASSKEY -> {
                PasskeyRequest.Unlock(id) to ""
            }

            else -> throw IllegalStateException("unknown action")
        }
    }

    private fun originOf(rpId: String, callingAppInfo: androidx.credentials.provider.CallingAppInfo?): String? =
        when (val decision = callingAppInfo?.let { validator.validateOrigin(rpId, it) }) {
            is OriginDecision.Web -> decision.origin
            is OriginDecision.Android -> decision.origin
            is OriginDecision.Refused -> {
                android.util.Log.w(TAG, "fulfillment origin refused: ${decision.reason}")
                null
            }

            null -> null // No caller identity (should not happen); refuse.
        }

    private fun failSilently(action: String?) {
        val result = Intent()
        if (action == BaluardCredentialProviderService.ACTION_CREATE_PASSKEY) {
            PendingIntentHandler.setCreateCredentialException(
                result,
                CreateCredentialNoCreateOptionException(),
            )
        } else {
            PendingIntentHandler.setGetCredentialException(result, NoCredentialException())
        }
        setResult(Activity.RESULT_OK, result)
        finish()
    }

    private fun ByteArray.toB64Url(): String =
        Base64.encodeToString(this, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun rpNameOf(requestJson: String): String? = runCatching {
        org.json.JSONObject(requestJson).optJSONObject("rp")?.optString("name")
    }.getOrNull()

    private fun userNameOf(requestJson: String): String? = runCatching {
        org.json.JSONObject(requestJson).optJSONObject("user")?.optString("name")
    }.getOrNull()

    private companion object {
        const val TAG = "PasskeyTrampoline"
    }
}
