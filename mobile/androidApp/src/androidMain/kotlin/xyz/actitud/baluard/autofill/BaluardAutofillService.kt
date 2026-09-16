package xyz.actitud.baluard.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import android.view.View
import android.view.autofill.AutofillId
import androidx.annotation.RequiresApi
import java.util.concurrent.Executors
import kotlinx.coroutines.runBlocking
import xyz.actitud.baluard.platform.FieldHeuristics
import xyz.actitud.baluard.platform.FieldKind
import xyz.actitud.baluard.platform.FieldView

/**
 * Baluard Android Autofill Service (plan §3.7, Phase 6).
 *
 * CRITICAL SECURITY INVARIANT (plan §3.2): this service runs as a SEPARATE OS
 * process (`:autofill`, enforced in the manifest and asserted by
 * AutofillProcessIsolationTest) with strict memory limits. It MUST unlock via
 * [AutofillSession.unlock], fed by the biometric-gated KEK from
 * [AutofillActivity]. The master-password Argon2id KDF (64-256 MB) never runs
 * here; it would OOM the process before completing.
 *
 * No network on the fill hot path: matching is `VaultState::autofill_query`
 * over the local vault only (plan D1/D9). Picker UI is RemoteViews only, no
 * Compose in this process (plan D7).
 *
 * Unlock model (plan D6): cold session -> response-level authentication, the
 * OS launches [AutofillActivity] for the BiometricPrompt ceremony, real
 * datasets come back through EXTRA_AUTHENTICATION_RESULT. Unlocked session ->
 * datasets are served directly. Every request re-checks the vault's own
 * auto-lock policy first.
 */
@RequiresApi(Build.VERSION_CODES.O)
class BaluardAutofillService : AutofillService() {

    private val executor = Executors.newSingleThreadExecutor()

    companion object {
        private const val TAG = "BaluardAutofill"

        // M10: onFailure messages can surface in system autofill diagnostics.
        // Static codes only; the real reason goes to logcat, never the callback.
        private const val ERR_NO_STRUCTURE = "no_structure"
        private const val ERR_NO_FIELDS = "no_fields"
        private const val ERR_FILL_FAILED = "fill_failed"
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            Log.w(TAG, "fill request had no structure")
            callback.onFailure(ERR_NO_STRUCTURE)
            return
        }

        executor.execute {
            try {
                val form = parseForm(structure)
                if (form == null) {
                    Log.i(TAG, "no autofillable fields; ignoring")
                    callback.onFailure(ERR_NO_FIELDS)
                    return@execute
                }

                val response = runBlocking {
                    AutofillSession.lockIfExpired()
                    if (AutofillSession.ensureOpen()) {
                        AutofillResponseBuilder.filledResponse(applicationContext, form.fields, form.target)
                            ?: AutofillResponseBuilder.saveOnlyResponse(
                                applicationContext,
                                form.fields,
                                form.target,
                            )
                    } else {
                        AutofillResponseBuilder.authenticationResponse(
                            applicationContext,
                            form.fields,
                            form.target,
                        )
                    }
                }

                if (cancellationSignal.isCanceled) return@execute
                callback.onSuccess(response)
            } catch (e: Exception) {
                Log.w(TAG, "autofill fill failed", e)
                callback.onFailure(ERR_FILL_FAILED)
            }
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // P4: route the submitted values into the main app for saving. The
        // save-only fill responses carry SaveInfo, so this fires on submit.
        callback.onSuccess()
    }

    /** Parsed login form: the fields to fill plus the match target. */
    data class Form(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?,
        val target: String,
    ) {
        val fields: AutofillResponseBuilder.TargetFields
            get() = AutofillResponseBuilder.TargetFields(usernameId, passwordId)
    }

    /**
     * Walk the AssistStructure with the layered heuristics in
     * [FieldHeuristics]. Real ViewNodes are adapted onto [FieldView] so the
     * classification logic stays unit-testable (plan P3).
     */
    private fun parseForm(structure: AssistStructure): Form? {
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var webDomain: String? = null

        val packageName = structure.activityComponent?.packageName

        for (i in 0 until structure.windowNodeCount) {
            val window = structure.getWindowNodeAt(i)
            walkNode(window.rootViewNode) { node ->
                val field = adapt(node)
                when (FieldHeuristics.classify(field)) {
                    FieldKind.Password -> {
                        if (passwordId == null) {
                            passwordId = node.autofillId
                            // Prefer the password field's own web origin.
                            node.webDomain?.let { webDomain = it }
                        }
                    }
                    FieldKind.Username -> {
                        if (usernameId == null) usernameId = node.autofillId
                    }
                    FieldKind.Other -> Unit
                }
                // WebView containers report the origin without being fields.
                if (webDomain == null) node.webDomain?.let { webDomain = it }
            }
        }

        if (usernameId == null && passwordId == null) return null
        val target = FieldHeuristics.targetFor(packageName, webDomain) ?: return null
        return Form(usernameId, passwordId, target)
    }

    private fun adapt(node: AssistStructure.ViewNode): FieldView = FieldView(
        autofillId = node.autofillId,
        hints = node.autofillHints?.toList().orEmpty(),
        inputType = node.inputType,
        idEntry = node.idEntry,
        hint = node.hint,
        text = node.text?.toString(),
        htmlAutocomplete = node.htmlInfo?.attributes
            ?.firstOrNull { it.first.equals("autocomplete", ignoreCase = true) }?.second,
        webDomain = node.webDomain,
    )

    private fun walkNode(node: AssistStructure.ViewNode, visit: (AssistStructure.ViewNode) -> Unit) {
        visit(node)
        for (i in 0 until node.childCount) walkNode(node.getChildAt(i), visit)
    }
}
