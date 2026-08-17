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

    suspend fun load(vault: MobileVault, id: String) {
        error = null
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
)

data class FieldRow(
    val spec: FieldSpec,
    val value: String,
)
