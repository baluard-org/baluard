package xyz.actitud.baluard.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import java.util.concurrent.Executors

/**
 * Baluard Android Autofill Service (plan §3.7).
 *
 * CRITICAL SECURITY INVARIANT (plan §3.2): this service runs as a SEPARATE OS
 * process with strict memory limits. It MUST unlock via [MobileVault.unlockWithKek]
 * using a biometric-gated KEK retrieved from the AndroidKeystore — NEVER the
 * master-password Argon2id KDF (a 64-256 MB KDF would OOM the service before
 * completing). The main app can run the full KDF; this process cannot.
 *
 * No network sync on the onFillRequest hot path: query a local cipher index
 * only. The service is native Kotlin (NOT Compose) for fast cold start + low
 * memory. A simpler View-based credential picker renders via RemoteViews.
 */
@RequiresApi(Build.VERSION_CODES.O)
class BaluardAutofillService : AutofillService() {

    private val executor = Executors.newSingleThreadExecutor()

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        // Phase 6 scaffold: parse the AssistStructure for username/password
        // fields + the package domain, then match against the vault index.
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onFailure("no structure")
            return
        }

        // Run the parse + match off the main thread (the service has seconds
        // of budget). The KEK-gated unlock + index read happen here.
        executor.execute {
            try {
                val parsed = parseAutofillFields(structure)
                if (parsed.usernameId == null && parsed.passwordId == null) {
                    callback.onFailure("no autofillable fields")
                    return@execute
                }

                // TODO Phase 6: unlock via unlock_with_kek (KEK from AndroidKeystore,
                //   gated by BiometricPrompt), then list_ciphers + match by package
                //   domain. Build a Dataset per matching login. For the scaffold we
                //   return an empty response (no credentials yet) so the OS degrades
                //   gracefully instead of crashing.
                callback.onSuccess(FillResponse.Builder().build())
            } catch (e: Exception) {
                callback.onFailure(e.message ?: "fill failed")
            }
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // User submitted a login form elsewhere → offer to save it as a new cipher.
        // Phase 6 scaffold: parse the saved fields + prompt to add via the main app.
        callback.onSuccess()
    }

    /**
     * Walk the AssistStructure to find autofillable username/password fields
     * and the package domain (for matching). Mirrors the heuristic across app
     * implementations Chrome/banking/social use; a known-bad-app list lives in
     * the full impl (plan §6 risk: AssistStructure parsing is fragile).
     */
    private fun parseAutofillFields(structure: AssistStructure): ParsedFields {
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        for (i in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(i)
            walkNode(window.rootViewNode) { node ->
                val hints = node.autofillHints?.toList().orEmpty()
                val isUser = hints.contains(View.AUTOFILL_HINT_USERNAME) ||
                    hints.contains(View.AUTOFILL_HINT_EMAIL_ADDRESS)
                val isPass = hints.contains(View.AUTOFILL_HINT_PASSWORD)
                if (isPass && passwordId == null) passwordId = node.autofillId
                else if (isUser && usernameId == null) usernameId = node.autofillId
            }
        }
        return ParsedFields(usernameId, passwordId, structure.activityComponent?.packageName)
    }

    private fun walkNode(node: AssistStructure.ViewNode, visit: (AssistStructure.ViewNode) -> Unit) {
        visit(node)
        for (i in 0 until node.childCount) walkNode(node.getChildAt(i), visit)
    }

    private data class ParsedFields(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?,
        val domain: String?,
    )

    @Suppress("unused")
    private fun presentation(text: String): RemoteViews =
        RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, text)
        }
}
