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

/**
 * Drives the cipher edit form (Phase 4). Loads an existing cipher (decrypt) or
 * starts a blank login; builds the daemon-wire JSON payload on save; calls
 * addCipher or updateCipher.
 *
 * The payload shape mirrors the daemon wire format (`{name, kind: {type, data}}`)
 * — see AGENTS.md "Daemon Wire Format". Login is fully modeled here; the other
 * 7 cipher types are scaffolds to be expanded per type (card numbers, identity
 * fields, SSH key material, etc.) before Phase 4 is feature-complete.
 */
class EditCipherViewModel(private val repo: VaultRepository) {
    private val _form = MutableStateFlow(EditForm())
    val form: StateFlow<EditForm> = _form.asStateFlow()

    private var existingId: String? = null

    fun setName(v: String) { _form.value = _form.value.copy(name = v) }
    fun setUsername(v: String) { _form.value = _form.value.copy(username = v) }
    fun setPassword(v: String) { _form.value = _form.value.copy(password = v) }
    fun setNotes(v: String) { _form.value = _form.value.copy(notes = v) }
    fun setFavorite(v: Boolean) { _form.value = _form.value.copy(favorite = v) }

    /** Load an existing cipher by id (decrypted) into the form. */
    suspend fun load(vault: MobileVault, id: String) {
        existingId = id
        runCatching {
            val raw = repo.getCipher(vault, id, decrypt = true)
            val obj = Json.parseToJsonElement(raw) as JsonObject
            val name = (obj["name"] as? JsonPrimitive)?.content ?: ""
            val kind = obj["kind"] as? JsonObject
            val data = kind?.get("data") as? JsonObject
            val username = (data?.get("username") as? JsonPrimitive)?.content ?: ""
            // Password may be absent (non-login); read defensively.
            val password = (data?.get("password") as? JsonPrimitive)?.content ?: ""
            val favorite = (obj["favorite"] as? JsonPrimitive)?.content == "true"
            _form.value = EditForm(
                name = name,
                username = username,
                password = password,
                favorite = favorite,
            )
        }
    }

    /** Persist: addCipher if new, updateCipher if editing. Returns the cipher id. */
    suspend fun save(vault: MobileVault): Result<String> {
        val f = _form.value
        val payload = buildLoginPayload(f, existingId)
        return runCatching {
            if (existingId != null) {
                repo.updateCipher(vault, payload)
                existingId!!
            } else {
                repo.addCipher(vault, payload)
            }
        }
    }

    /** Build the daemon-wire JSON for a login cipher. */
    private fun buildLoginPayload(f: EditForm, id: String?): String {
        val root = buildJsonObject {
            if (id != null) put("id", id)
            put("name", f.name)
            put("favorite", f.favorite)
            put("notes", JsonPrimitive(f.notes))
            put("kind", buildJsonObject {
                put("type", "login")
                put("data", buildJsonObject {
                    put("username", f.username)
                    put("password", f.password)
                    put("uris", kotlinx.serialization.json.buildJsonArray {})
                    put("totp_uri", JsonNull)
                    put("autofill_on_page_load", false)
                    put("password_revision_date", JsonNull)
                    put("favicon", JsonNull)
                    put("fido2_credentials", JsonNull)
                })
            })
        }
        return root.toString()
    }
}

data class EditForm(
    val name: String = "",
    val username: String = "",
    val password: String = "",
    val notes: String = "",
    val favorite: Boolean = false,
)
