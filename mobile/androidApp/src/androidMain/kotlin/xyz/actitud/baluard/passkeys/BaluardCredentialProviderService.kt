package xyz.actitud.baluard.passkeys

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.PublicKeyCredentialEntry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import xyz.actitud.baluard.auth.SharedVaultSession
import xyz.actitud.baluard.platform.VaultRegistry
import java.time.Instant

/**
 * Baluard as an Android credential provider — passkeys only (plan §4). Thin
 * service: Begin-phase listing rides the process-wide [SharedVaultSession]
 * so the sheet only ever shows credentials from a vault the user has
 * unlocked in the app; the unlock return leg re-lists after unlock.
 *
 * Listing refuses every caller whose origin fails [OriginValidator] — no
 * validated origin, no entry (§7 fail-closed; refusal is silent per §9).
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class BaluardCredentialProviderService : CredentialProviderService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val validator = OriginValidator(this)

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, androidx.credentials.exceptions.CreateCredentialException>,
    ) {
        if (xyz.actitud.baluard.BuildConfig.BALUARD_E2E) {
            android.util.Log.e("PasskeySvc", "beginCreate type=${request.type}")
        }
        val job = scope.launch {
            runCatching { handleCreateQuery(request) }
                .onSuccess { callback.onResult(it) }
                .onFailure {
                    android.util.Log.w(TAG, "begin create failed", it)
                    callback.onError(
                        androidx.credentials.exceptions.CreateCredentialUnknownException("listing failed"),
                    )
                }
        }
        cancellationSignal.setOnCancelListener {
            job.cancel()
            callback.onError(androidx.credentials.exceptions.CreateCredentialCancellationException())
        }
    }

    private suspend fun handleCreateQuery(
        request: BeginCreateCredentialRequest,
    ): BeginCreateCredentialResponse {
        val empty = BeginCreateCredentialResponse.Builder().build()
        if (request !is BeginCreatePublicKeyCredentialRequest) return empty
        val requestJson = request.requestJson
        if (requestJson.isEmpty()) return empty
        val rp = PasskeyLister.rpIdOf(requestJson) ?: return empty
        val callingApp = request.callingAppInfo
        if (callingApp == null) return empty // no caller identity = no validated origin
        val decision = validator.validateOrigin(rp, callingApp)
        if (decision is OriginDecision.Refused) {
            android.util.Log.w(TAG, "create origin refused: ${decision.reason}")
            return empty
        }
        val accountName = activeVaultName() ?: return empty
        val entry = CreateEntry.Builder(
            accountName = accountName,
            pendingIntent = trampolineIntent(
                context = this,
                action = ACTION_CREATE_PASSKEY,
                requestCode = ("create|$rp").hashCode(),
            ),
        )
            .setDescription("The passkey will be saved to your vault.")
            .setLastUsedTime(Instant.now())
            .setAutoSelectAllowed(true)
            .build()
        return BeginCreateCredentialResponse.Builder()
            .setCreateEntries(listOf(entry))
            .build()
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, androidx.credentials.exceptions.GetCredentialException>,
    ) {
        val job = scope.launch {
            runCatching { handleGetQuery(request) }
                .onSuccess { callback.onResult(it) }
                .onFailure {
                    android.util.Log.w(TAG, "begin get failed", it)
                    callback.onError(
                        androidx.credentials.exceptions.GetCredentialUnknownException("listing failed"),
                    )
                }
        }
        cancellationSignal.setOnCancelListener {
            job.cancel()
            callback.onError(androidx.credentials.exceptions.GetCredentialCancellationException())
        }
    }

    private suspend fun handleGetQuery(
        request: BeginGetCredentialRequest,
    ): BeginGetCredentialResponse {
        val options = request.beginGetCredentialOptions
            .filterIsInstance<BeginGetPublicKeyCredentialOption>()
        if (options.isEmpty()) return BeginGetCredentialResponse(emptyList(), emptyList())

        val activePath = activeVaultPath()
        val vault = activePath?.let { SharedVaultSession.multi.vaultFor(it) }
            ?.takeIf { runCatching { it.isUnlocked() }.getOrDefault(false) }
        if (activePath == null || vault == null) {
            return BeginGetCredentialResponse(
                authenticationActions = listOf(
                    AuthenticationAction(
                        title = "Unlock",
                        pendingIntent = trampolineIntent(
                            context = this,
                            action = ACTION_UNLOCK_PASSKEY,
                            requestCode = "unlock".hashCode(),
                        ),
                    ),
                ),
            )
        }

        val entries = mutableListOf<PublicKeyCredentialEntry>()
        for (option in options) {
            // No caller identity at Begin (androidx attaches callingAppInfo
            // only to the fulfillment request) — the trampoline gate enforces
            // §7; Begin lists by rp id alone.
            val rp = PasskeyLister.rpIdOf(option.requestJson) ?: continue
            val allowed = PasskeyLister.allowIdsOf(option.requestJson)
            val matches = PasskeyLister.list(vault, rp, allowed)
            entries += matches.map { pk ->
                PublicKeyCredentialEntry.Builder(
                    context = this,
                    username = pk.userName ?: "No username",
                    pendingIntent = trampolineIntent(
                        context = this,
                        action = ACTION_GET_PASSKEY,
                        requestCode = ("get|" + pk.credentialId).hashCode(),
                        credentialId = pk.credentialId,
                    ),
                    beginGetPublicKeyCredentialOption = option,
                )
                    .setAutoSelectAllowed(false)
                    .build()
            }
        }
        android.util.Log.d(TAG, "listing ${entries.size} passkey entries")
        return BeginGetCredentialResponse.Builder()
            .setCredentialEntries(entries)
            .build()
    }

    override fun onClearCredentialStateRequest(
        request: androidx.credentials.provider.ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, androidx.credentials.exceptions.ClearCredentialException>,
    ) {
        // Sign-out flows invoke this; an error response is pointless noise.
        callback.onResult(null)
    }

    // ── vault access (main-process shared session) ──

    private fun activeVaultPath(): String? {
        val vaults = VaultRegistry.listVaults()
        val active = vaults.firstOrNull { it.path == VaultRegistry.loadActiveVault() }?.path
        return active ?: vaults.firstOrNull()?.path
    }

    private fun activeVaultName(): String? {
        val vaults = VaultRegistry.listVaults()
        val active = vaults.firstOrNull { it.path == VaultRegistry.loadActiveVault() }
        return (active ?: vaults.firstOrNull())?.name
    }

    private fun trampolineIntent(
        context: Context,
        action: String,
        requestCode: Int,
        credentialId: String? = null,
    ): PendingIntent {
        val intent = Intent(context, PasskeyTrampolineActivity::class.java).apply {
            this.action = action
            credentialId?.let { putExtra(EXTRA_CREDENTIAL_ID, it) }
        }
        // FLAG_MUTABLE: the framework injects the request extras into this
        // intent — immutable kills the flow (§4).
        return PendingIntent.getActivity(
            context,
            requestCode,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    companion object {
        private const val TAG = "BaluardCredProvider"
        const val BUNDLE_KEY_REQUEST_JSON = "androidx.credentials.BUNDLE_KEY_REQUEST_JSON"
        const val ACTION_CREATE_PASSKEY = "xyz.actitud.baluard.ACTION_CREATE_PASSKEY"
        const val ACTION_GET_PASSKEY = "xyz.actitud.baluard.ACTION_GET_PASSKEY"
        const val ACTION_UNLOCK_PASSKEY = "xyz.actitud.baluard.ACTION_UNLOCK_PASSKEY"
        const val EXTRA_CREDENTIAL_ID = "xyz.actitud.baluard.EXTRA_CREDENTIAL_ID"
        const val EXTRA_REQUEST_ID = "xyz.actitud.baluard.EXTRA_REQUEST_ID"
    }
}
