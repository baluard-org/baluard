package xyz.actitud.baluard.detail

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.data.VaultRepository

/**
 * Loads one decrypted cipher into a render-ready [DetailState]. Parses the
 * daemon-wire JSON ({name, favorite, notes, kind: {type, data}}) once and
 * maps `data` through [fieldsFor]; unknown types degrade to name + notes
 * (never a crash on a future type).
 */
class CipherDetailViewModel(private val repo: VaultRepository) {

    var state: DetailState? by mutableStateOf(null)
        private set
    var error: String? by mutableStateOf(null)
        private set

    /** True when the loaded cipher is already in trash (delete = purge). */
    var inTrash: Boolean by mutableStateOf(false)
        private set
    suspend fun load(vault: MobileVault, id: String) {
        error = null
        inTrash = runCatching { repo.listTrash(vault).any { it.id == id } }.getOrDefault(false)
        try {
            val raw = repo.getCipher(vault, id, decrypt = true)
            val obj = Json.parseToJsonElement(raw) as JsonObject
            val kind = obj["kind"] as? JsonObject
            val tag = (kind?.get("type") as? JsonPrimitive)?.content ?: "login"
            val data = kind?.get("data") as? JsonObject

            val rows = fieldsFor(tag).mapNotNull { spec ->
                val v = (data?.get(spec.wireKey) as? JsonPrimitive)?.content
                if (v.isNullOrBlank()) null else FieldRow(spec, v)
            }

            state = DetailState(
                id = id,
                name = (obj["name"] as? JsonPrimitive)?.content ?: "",
                favorite = (obj["favorite"] as? JsonPrimitive)?.content == "true",
                typeTag = tag,
                fields = rows,
                uris = parseUris(data),
                notes = (obj["notes"] as? JsonPrimitive)?.content?.takeIf { it.isNotBlank() },
                hasTotp = !(data?.get("totp_uri") as? JsonPrimitive)?.content.isNullOrBlank(),
                customFields = parseCustomFields(data),
                passkeys = parsePasskeys(data),
                attachments = parseAttachments(data),
            )
        } catch (e: Exception) {
            error = e.message
        }
    }

    /** Delete the loaded cipher (trash semantics — the runtime soft-deletes).
     * The caller navigates back and bumps its reload revision. */
    suspend fun delete(vault: MobileVault, id: String) {
        error = null
        try {
            repo.deleteCipher(vault, id)
            state = null
        } catch (e: Exception) {
            error = e.message
        }
    }

    /** Login URIs live under uris: [{uri, matchStrategy}]. */
    private fun parseUris(data: JsonObject?): List<String> =
        (data?.get("uris") as? kotlinx.serialization.json.JsonArray)
            ?.mapNotNull { (it as? JsonObject)?.get("uri") as? JsonPrimitive }
            ?.map { it.content }
            ?.filter { it.isNotBlank() }
            .orEmpty()

    /**
     * Custom fields under custom_fields: [{name, value, field_type}].
     * field_type wire values: unit variants are plain strings
     * ("Text"/"Hidden"/"Boolean"); Linked serializes as an object
     * {"Linked":"..."} and renders as plain text (desktop parity).
     */
    private fun parseCustomFields(data: JsonObject?): List<CustomFieldRow> =
        (data?.get("custom_fields") as? kotlinx.serialization.json.JsonArray)
            ?.mapNotNull { el ->
                val o = el as? JsonObject ?: return@mapNotNull null
                val name = (o["name"] as? JsonPrimitive)?.content ?: return@mapNotNull null
                val value = (o["value"] as? JsonPrimitive)?.content ?: ""
                val ft = (o["field_type"] as? JsonPrimitive)?.content
                CustomFieldRow(
                    name = name,
                    value = value,
                    hidden = ft == "Hidden",
                    boolean = ft == "Boolean",
                )
            }
            .orEmpty()

    /** Passkeys under fido2_credentials (embedded in Login, desktop parity). */
    private fun parsePasskeys(data: JsonObject?): List<PasskeyRow> =
        (data?.get("fido2_credentials") as? kotlinx.serialization.json.JsonArray)
            ?.mapNotNull { el ->
                val o = el as? JsonObject ?: return@mapNotNull null
                val rpId = (o["rp_id"] as? JsonPrimitive)?.content ?: return@mapNotNull null
                PasskeyRow(
                    name = (o["name"] as? JsonPrimitive)?.content
                        ?: (o["rp_name"] as? JsonPrimitive)?.content
                        ?: rpId,
                    rpId = rpId,
                    user = (o["user_display_name"] as? JsonPrimitive)?.content
                        ?: (o["user_name"] as? JsonPrimitive)?.content
                        ?: "",
                    created = (o["creation_date"] as? JsonPrimitive)?.content
                        ?.toLongOrNull()?.let(::formatEpochDate),
                    missingKey = (o["private_key_missing"] as? JsonPrimitive)?.content == "true",
                )
            }
            .orEmpty()

    /** Attachment metadata under attachments: [{filename, size, ...}]. */
    private fun parseAttachments(data: JsonObject?): List<AttachmentRow> =
        (data?.get("attachments") as? kotlinx.serialization.json.JsonArray)
            ?.mapNotNull { el ->
                val o = el as? JsonObject ?: return@mapNotNull null
                val filename = (o["filename"] as? JsonPrimitive)?.content
                    ?: return@mapNotNull null
                AttachmentRow(
                    filename = filename,
                    sizeLabel = formatBytes((o["size"] as? JsonPrimitive)?.content?.toLongOrNull() ?: 0L),
                )
            }
            .orEmpty()
}

data class DetailState(
    val id: String,
    val name: String,
    val favorite: Boolean,
    val typeTag: String,
    val fields: List<FieldRow>,
    val uris: List<String>,
    val notes: String?,
    val hasTotp: Boolean,
    val customFields: List<CustomFieldRow> = emptyList(),
    val passkeys: List<PasskeyRow> = emptyList(),
    val attachments: List<AttachmentRow> = emptyList(),
)

data class FieldRow(
    val spec: FieldSpec,
    val value: String,
)

/** A user-defined custom field (desktop parity). */
data class CustomFieldRow(
    val name: String,
    val value: String,
    /** Hidden fields render masked with a reveal toggle (like a password). */
    val hidden: Boolean,
    /** Boolean fields render a yes/no chip instead of a copyable value. */
    val boolean: Boolean,
)

/** A stored passkey, display-only (delete stays desktop-only for now). */
data class PasskeyRow(
    val name: String,
    val rpId: String,
    val user: String,
    val created: String?,
    /** true for BW imports without the private key (re-register needed). */
    val missingKey: Boolean,
)

/** Attachment metadata row (download lands with the mobile attachment FFI). */
data class AttachmentRow(
    val filename: String,
    val sizeLabel: String,
)

/**
 * Epoch seconds -> "YYYY-MM-DD" without a datetime dependency
 * (civil-from-days, Howard Hinnant's algorithm).
 */
internal fun formatEpochDate(epochSeconds: Long): String {
    val days = epochSeconds / 86_400
    val z0 = days + 719_468
    val era = (if (z0 >= 0) z0 else z0 - 146_096) / 146_097
    val doe = z0 - era * 146_097
    val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
    val y = yoe + era * 400
    val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
    val mp = (5 * doy + 2) / 153
    val d = doy - (153 * mp + 2) / 5 + 1
    val m = if (mp < 10) mp + 3 else mp - 9
    val year = if (m <= 2) y + 1 else y
    val yStr = year.toString().padStart(4, '0')
    val mStr = m.toString().padStart(2, '0')
    val dStr = d.toString().padStart(2, '0')
    return "$yStr-$mStr-$dStr"
}

/** Human byte size (B / KB / MB), one decimal below 10. */
internal fun formatBytes(bytes: Long): String = when {
    bytes >= 1_048_576 -> {
        val mb10 = bytes * 10 / 1_048_576
        "${mb10 / 10}.${mb10 % 10} MB"
    }
    bytes >= 1024 -> {
        val kb10 = bytes * 10 / 1024
        "${kb10 / 10}.${kb10 % 10} KB"
    }
    else -> "$bytes B"
}
