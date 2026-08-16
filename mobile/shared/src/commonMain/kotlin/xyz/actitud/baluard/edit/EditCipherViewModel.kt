package xyz.actitud.baluard.edit

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.detail.fieldsFor

/**
 * Drives the cipher edit form for all 8 types (plan §3: create/edit any
 * type). The form is generic: field rows come from [fieldsFor] (the same
 * schema the detail screen renders), keyed by wire field name.
 *
 * Merge-on-save semantics: the loaded cipher's `data` object is captured
 * whole and only the edited keys are overwritten. This preserves fields the
 * form does not model (passkeys, URIs, TOTP seed, password revision date) —
 * replacing the object wholesale would wipe them, since update_cipher
 * replaces `kind` entirely (AGENTS.md "Daemon Wire Format").
 */
class EditCipherViewModel(private val repo: VaultRepository) {
    private val _form = MutableStateFlow(EditForm())
    val form: StateFlow<EditForm> = _form.asStateFlow()

    private var existingId: String? = null

    /** Original decrypted `data` object; null for a new entry. */
    private var originalData: JsonObject? = null

    fun setName(v: String) { _form.value = _form.value.copy(name = v) }
    fun setNotes(v: String) { _form.value = _form.value.copy(notes = v) }
    fun setFavorite(v: Boolean) { _form.value = _form.value.copy(favorite = v) }

    /** Set one dynamic field value (wire key). */
    fun setField(key: String, value: String) {
        _form.value = _form.value.copy(values = _form.value.values + (key to value))
    }

    /** Switch type while composing a NEW entry (edit keeps the stored type). */
    fun setType(tag: String) {
        if (existingId != null) return
        _form.value = _form.value.copy(typeTag = tag, values = emptyMap())
    }

    /** Blank the form for a new entry (shared VM instance across screens). */
    fun reset() {
        existingId = null
        originalData = null
        _form.value = EditForm()
    }

    /** Load an existing cipher by id (decrypted) into the form. */
    suspend fun load(vault: MobileVault, id: String) {
        runCatching {
            val raw = repo.getCipher(vault, id, decrypt = true)
            val obj = Json.parseToJsonElement(raw) as JsonObject
            val kind = obj["kind"] as? JsonObject
            val tag = (kind?.get("type") as? JsonPrimitive)?.content ?: "login"
            val data = kind?.get("data") as? JsonObject ?: JsonObject(emptyMap())

            existingId = id
            originalData = data
            _form.value = EditForm(
                name = (obj["name"] as? JsonPrimitive)?.content ?: "",
                typeTag = tag,
                notes = (obj["notes"] as? JsonPrimitive)?.content ?: "",
                favorite = (obj["favorite"] as? JsonPrimitive)?.content == "true",
                values = fieldsFor(tag).mapNotNull { spec ->
                    val v = (data[spec.wireKey] as? JsonPrimitive)?.content
                    if (v.isNullOrBlank()) null else spec.wireKey to v
                }.toMap(),
            )
        }
    }

    /** Persist: addCipher if new, updateCipher if editing. Returns the cipher id. */
    suspend fun save(vault: MobileVault): Result<String> {
        val f = _form.value
        val payload = buildPayload(f, existingId)
        return runCatching {
            if (existingId != null) {
                repo.updateCipher(vault, payload)
                existingId!!
            } else {
                repo.addCipher(vault, payload)
            }
        }
    }

    /**
     * Daemon-wire JSON: {name, favorite, notes, kind: {type, data}}. `data`
     * starts from the original object (preserving unmodeled fields) and
     * overlays the form values; a cleared field sends null so the stored
     * value is removed. New entries start from an empty object (nulls).
     */
    private fun buildPayload(f: EditForm, id: String?): String {
        val data = buildJsonObject {
            originalData?.forEach { (k, v) -> put(k, v) }
            fieldsFor(f.typeTag).forEach { spec ->
                val v = f.values[spec.wireKey].orEmpty()
                put(spec.wireKey, if (v.isBlank()) JsonNull else JsonPrimitive(v))
            }
        }
        val root = buildJsonObject {
            if (id != null) put("id", id)
            put("name", f.name)
            put("favorite", f.favorite)
            put("notes", if (f.notes.isBlank()) JsonNull else JsonPrimitive(f.notes))
            put("kind", buildJsonObject {
                put("type", f.typeTag)
                put("data", data)
            })
        }
        return root.toString()
    }
}

data class EditForm(
    val name: String = "",
    val typeTag: String = "login",
    val notes: String = "",
    val favorite: Boolean = false,
    /** Dynamic field values by wire key (see [fieldsFor]). */
    val values: Map<String, String> = emptyMap(),
)
