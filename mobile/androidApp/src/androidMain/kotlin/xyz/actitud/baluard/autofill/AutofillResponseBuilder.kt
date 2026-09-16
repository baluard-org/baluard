package xyz.actitud.baluard.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import xyz.actitud.baluard.R
import xyz.actitud.baluard.i18n.t

/**
 * Shared FillResponse construction for the service (direct path, session
 * already unlocked) and [AutofillActivity] (post-biometric path). One builder,
 * one presentation layout, identical save-info on every path (plan D7/D8).
 */
object AutofillResponseBuilder {

    /** Fields worth filling, as passed between service and activity. */
    data class TargetFields(val usernameId: AutofillId?, val passwordId: AutofillId?) {
        val ids: Array<AutofillId>
            get() = listOfNotNull(usernameId, passwordId).toTypedArray()
    }

    /**
     * Response-level authentication (plan D6): pre-unlock we cannot know
     * which logins match, so the whole response is gated behind one generic
     * "Unlock Baluard" entry. The OS launches [AutofillActivity] on tap; the
     * real datasets come back via EXTRA_AUTHENTICATION_RESULT.
     */
    fun authenticationResponse(context: Context, fields: TargetFields, target: String): FillResponse {
        val intent = Intent(context, AutofillActivity::class.java).apply {
            putExtra(AutofillActivity.EXTRA_TARGET, target)
            putParcelableArrayListExtra(AutofillActivity.EXTRA_IDS, ArrayList(fields.ids.toList()))
        }
        val pending = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return FillResponse.Builder()
            .setAuthentication(fields.ids, pending.intentSender, unlockPresentation(context))
            .setSaveInfo(saveInfo(fields))
            .build()
    }

    /**
     * Direct datasets for an unlocked session. One dataset per match; values
     * are only attached to ids the form actually has. Returns null when the
     * query yielded nothing, in which case the caller falls back to a
     * save-only response so on-save capture still works.
     */
    suspend fun filledResponse(context: Context, fields: TargetFields, target: String): FillResponse? {
        val matches = AutofillSession.matches(target)
        if (matches.isEmpty()) return null

        val builder = FillResponse.Builder()
        for (match in matches) {
            val (username, password) = AutofillSession.credential(match.id) ?: continue
            // Presentation lives in the Dataset constructor at this API level
            // (there is no setPresentation(RemoteViews) on the builder).
            val ds = Dataset.Builder(datasetPresentation(context, match.name, username))
            if (fields.usernameId != null && username != null) {
                ds.setValue(fields.usernameId, AutofillValue.forText(username))
            }
            if (fields.passwordId != null && password != null) {
                ds.setValue(fields.passwordId, AutofillValue.forText(password))
            }
            builder.addDataset(ds.build())
        }
        return builder.setSaveInfo(saveInfo(fields)).build()
    }

    /**
     * Empty-but-saveable response: keeps on-save capture alive when nothing
     * matches (plan D8: SaveInfo with FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE, or
     * onSaveRequest never fires once SPAs destroy the form).
     */
    fun saveOnlyResponse(context: Context, fields: TargetFields, target: String): FillResponse =
        FillResponse.Builder()
            .setSaveInfo(saveInfo(fields))
            .build()

    private fun saveInfo(fields: TargetFields): SaveInfo {
        val builder = SaveInfo.Builder(
            SaveInfo.SAVE_DATA_TYPE_PASSWORD,
            listOfNotNull(fields.usernameId, fields.passwordId).toTypedArray(),
        )
        return builder
            .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            .build()
    }

    private fun unlockPresentation(context: Context): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(R.id.autofill_item_title, t("login.biometricTitle"))
            setTextViewText(R.id.autofill_item_subtitle, t("autofill.unlockHint"))
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }

    private fun datasetPresentation(context: Context, name: String, username: String?): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset_item).apply {
            setTextViewText(R.id.autofill_item_title, name)
            setTextViewText(
                R.id.autofill_item_subtitle,
                username?.takeIf { it.isNotBlank() } ?: t("autofill.noUsername"),
            )
            setImageViewResource(R.id.autofill_item_icon, R.mipmap.ic_launcher)
        }
}
