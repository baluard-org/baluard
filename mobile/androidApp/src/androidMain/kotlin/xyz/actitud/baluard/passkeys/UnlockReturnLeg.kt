package xyz.actitud.baluard.passkeys

import xyz.actitud.baluard.i18n.t
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.PublicKeyCredentialEntry
import xyz.actitud.baluard.auth.SharedVaultSession
import xyz.actitud.baluard.platform.VaultRegistry

/**
 * Rebuilds Begin entries after the in-app unlock — the return leg that must
 * answer the waiting sheet (plan §4: finishing without
 * setBeginGetCredentialResponse silently blanks it). Shared by nothing
 * else; the service lists directly.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
object UnlockReturnLeg {

    suspend fun answer(
        context: Context,
        validator: OriginValidator,
    ): Boolean {
        val request = PasskeyRequestManager.frameworkBegin ?: return false
        val options = request.beginGetCredentialOptions
            .filterIsInstance<androidx.credentials.provider.BeginGetPublicKeyCredentialOption>()
        val entries = mutableListOf<PublicKeyCredentialEntry>()
        // Same fallback the credential service uses: no active pointer
        // must not answer an empty sheet when exactly one vault exists.
        val activePath = VaultRegistry.loadActiveVault()
            ?: VaultRegistry.listVaults().firstOrNull()?.path
        val vault = activePath?.let { SharedVaultSession.multi.vaultFor(it) }
            ?.takeIf { runCatching { it.isUnlocked() }.getOrDefault(false) }
        if (vault != null) {
            for (option in options) {
                val rp = PasskeyLister.rpIdOf(option.requestJson) ?: continue
                val allowed = PasskeyLister.allowIdsOf(option.requestJson)
                // No caller identity on the Begin request; the gate ran at
                // entry selection (the trampoline).
                val matches = PasskeyLister.list(vault, rp, allowed)
                entries += matches.map { pk ->
                    PublicKeyCredentialEntry.Builder(
                        context = context,
                        username = pk.userName ?: t("passkey.noUsername"),
                        pendingIntent = entryPendingIntent(context, pk.credentialId),
                        beginGetPublicKeyCredentialOption = option,
                    )
                        .setAutoSelectAllowed(false)
                        .build()
                }
            }
        }
        val intent = Intent()
        androidx.credentials.provider.PendingIntentHandler.setBeginGetCredentialResponse(
            intent,
            BeginGetCredentialResponse.Builder()
                .setCredentialEntries(entries)
                .setAuthenticationActions(emptyList())
                .build(),
        )
        (context as android.app.Activity).setResult(android.app.Activity.RESULT_OK, intent)
        return true
    }

    private fun entryPendingIntent(context: Context, credentialId: String): PendingIntent {
        val intent = Intent(context, PasskeyTrampolineActivity::class.java).apply {
            action = BaluardCredentialProviderService.ACTION_GET_PASSKEY
            putExtra(BaluardCredentialProviderService.EXTRA_CREDENTIAL_ID, credentialId)
        }
        return PendingIntent.getActivity(
            context,
            ("get|$credentialId").hashCode(),
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }
}
