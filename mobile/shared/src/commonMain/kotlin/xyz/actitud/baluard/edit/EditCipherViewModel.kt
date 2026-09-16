package xyz.actitud.baluard.edit

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import xyz.actitud.baluard.platform.platformLogE
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import xyz.actitud.baluard.data.MobileFolderInfo
import xyz.actitud.baluard.MobileVault
import xyz.actitud.baluard.PasswordConfig
import xyz.actitud.baluard.data.VaultRepository
import xyz.actitud.baluard.detail.fieldsFor
import xyz.actitud.baluard.detail.str
import xyz.actitud.baluard.detail.str

/**
 * Drives the cipher edit form for all 8 types (plan §3: create/edit any
 * type), at desktop parity: scalar schema fields, login URIs with match
 * strategy, TOTP seed, custom fields (Text/Hidden/Boolean/Linked), tags,
 * folder, favorite and reprompt.
 *
 * Merge-on-save semantics: the loaded cipher's `data` object is captured
 * whole and only the edited keys are overwritten. This preserves fields the
 * form does not model (passkeys, password revision date, favicon) —
 * replacing the object wholesale would wipe them, since update_cipher
 * replaces `kind` entirely (AGENTS.md "Daemon Wire Format"). URIs and the
 * TOTP seed ARE modeled: load() fills them from the cipher, so an untouched
 * edit re-emits them unchanged.
 *
 * Root-level keys (tags, custom_fields, folder_id, reprompt) are always sent
 * explicitly, matching the desktop form's full-replace behavior: an empty
 * tag/field list clears what was there.
 */
class EditCipherViewModel(private val repo: VaultRepository) {
    private val _form = MutableStateFlow(EditForm())
    val form: StateFlow<EditForm> = _form.asStateFlow()

    /** Non-null when loading an existing cipher failed (corrupt JSON, FFI error). */
    var loadError: String? by mutableStateOf(null)
        private set

    private val _folders = MutableStateFlow<List<MobileFolderInfo>>(emptyList())
    val folders: StateFlow<List<MobileFolderInfo>> = _folders.asStateFlow()

    private val _allTags = MutableStateFlow<List<String>>(emptyList())
    val allTags: StateFlow<List<String>> = _allTags.asStateFlow()

    private var existingId: String? = null

    /** Original decrypted `data` object; null for a new entry. */
    private var originalData: JsonObject? = null

    fun setName(v: String) { _form.value = _form.value.copy(name = v) }
    fun setNotes(v: String) { _form.value = _form.value.copy(notes = v) }
    fun setFavorite(v: Boolean) { _form.value = _form.value.copy(favorite = v) }
    fun setReprompt(v: Boolean) { _form.value = _form.value.copy(reprompt = v) }
    fun setTotpUri(v: String) { _form.value = _form.value.copy(totpUri = v) }
    fun setFolderId(v: String?) { _form.value = _form.value.copy(folderId = v) }

    /** Set one dynamic field value (wire key). */
    fun setField(key: String, value: String) {
        _form.value = _form.value.copy(values = _form.value.values + (key to value))
    }

    /** Switch type while composing a NEW entry (edit keeps the stored type). */
    fun setType(tag: String) {
        if (existingId != null) return
        _form.value = _form.value.copy(typeTag = tag, values = emptyMap())
    }

    // ── URIs (login) ──

    fun addUri() { _form.value = _form.value.copy(uris = _form.value.uris + UriRow()) }
    fun removeUri(index: Int) {
        _form.value = _form.value.copy(uris = _form.value.uris.filterIndexed { i, _ -> i != index })
    }
    fun setUri(index: Int, uri: String) = mutateUri(index) { it.copy(uri = uri) }
    fun setUriMatch(index: Int, match: String?) = mutateUri(index) { it.copy(matchStrategy = match) }

    private fun mutateUri(index: Int, edit: (UriRow) -> UriRow) {
        _form.value = _form.value.copy(uris = _form.value.uris.mapIndexed { i, r -> if (i == index) edit(r) else r })
    }

    // ── Custom fields ──

    fun addCustomField() {
        _form.value = _form.value.copy(customFields = _form.value.customFields + CustomFieldEdit())
    }
    fun removeCustomField(index: Int) {
        _form.value = _form.value.copy(customFields = _form.value.customFields.filterIndexed { i, _ -> i != index })
    }
    fun setCustomFieldName(index: Int, name: String) = mutateCustomField(index) { it.copy(name = name) }
    fun setCustomFieldValue(index: Int, value: String) = mutateCustomField(index) { it.copy(value = value) }

    /** Type switch, desktop parity: Boolean seeds "false", Linked clears the value. */
    fun setCustomFieldType(index: Int, type: String) = mutateCustomField(index) {
        when {
            type == "Linked" -> it.copy(fieldType = "Linked", linkedTarget = it.linkedTarget ?: "LoginUsername", value = "")
            type == "Boolean" -> it.copy(fieldType = "Boolean", value = it.value.ifBlank { "false" })
            else -> it.copy(fieldType = type)
        }
    }
    fun setCustomFieldLinkedTarget(index: Int, target: String) = mutateCustomField(index) { it.copy(linkedTarget = target) }

    private fun mutateCustomField(index: Int, edit: (CustomFieldEdit) -> CustomFieldEdit) {
        _form.value = _form.value.copy(customFields = _form.value.customFields.mapIndexed { i, f -> if (i == index) edit(f) else f })
    }

    // ── Tags ──

    /** Desktop parity: lowercase, deduped case-insensitively, max 20 x 64 chars. */
    fun addTag(raw: String) {
        val tag = raw.trim().lowercase().removeSuffix(",")
        val f = _form.value
        if (tag.isEmpty() || f.tags.size >= 20 || tag.length > 64) return
        if (f.tags.any { it.equals(tag, ignoreCase = true) }) return
        _form.value = f.copy(tags = f.tags + tag)
    }
    fun removeTag(tag: String) {
        _form.value = _form.value.copy(tags = _form.value.tags - tag)
    }

    /** Blank the form for a new entry (shared VM instance across screens). */
    fun reset() {
        existingId = null
        originalData = null
        loadError = null
        _form.value = EditForm()
    }

    /** Folder options for the picker; failures leave the previous (or empty) list. */
    suspend fun loadFolders(vault: MobileVault) {
        _folders.value = runCatching { repo.listFolders(vault) }.getOrDefault(_folders.value)
    }

    /** All known tags for autocomplete; failures leave the previous list. */
    suspend fun loadTags(vault: MobileVault) {
        _allTags.value = runCatching { repo.listTags(vault) }.getOrDefault(_allTags.value)
    }

    /** Inline password generation with desktop's knobs (length 8-64,
     * uppercase / numbers / symbols toggles). */
    suspend fun generatePassword(length: Int, upper: Boolean, numbers: Boolean, symbols: Boolean): String =
        repo.generatePassword(
            PasswordConfig(length.coerceIn(1, 128).toUInt(), upper, numbers, symbols),
        ).getOrElse { "" }

    /** SSH keypair generation (desktop SshKeyGenerator parity). Fills the
     * public_key / private_key / key_fingerprint form fields. Returns false on
     * FFI or parse failure (caller surfaces the error). */
    suspend fun generateSshKey(vault: MobileVault, keyType: String): Boolean {
        val raw = runCatching { repo.sshGenerateKey(vault, keyType) }.getOrNull() ?: return false
        val obj = runCatching { Json.parseToJsonElement(raw) as? JsonObject }.getOrNull() ?: return false
        fun f(k: String): String = obj.str(k).orEmpty()
        val publicKey = f("public_key")
        val privateKey = f("private_key")
        val fingerprint = f("fingerprint")
        if (publicKey.isBlank() || privateKey.isBlank()) return false
        _form.value = _form.value.copy(values = _form.value.values + mapOf(
            "public_key" to publicKey,
            "private_key" to privateKey,
            "key_fingerprint" to fingerprint,
        ))
        return true
    }

    /** Load an existing cipher by id (decrypted) into the form. */
    suspend fun load(vault: MobileVault, id: String) {
        // Clear the previous cipher FIRST: on a failed load the Save button
        // (form.name.isNotBlank) would otherwise stay enabled and overwrite
        // the wrong entry with stale form data.
        loadError = null
        existingId = null
        originalData = null
        _form.value = EditForm()
        try {
            val raw = repo.getCipher(vault, id, decrypt = true)
            existingId = id
            originalData = extractData(raw)
            _form.value = parseLoadedCipher(raw)
        } catch (e: kotlin.coroutines.cancellation.CancellationException) {
            throw e
        } catch (e: Exception) {
            // A corrupt cipher must not silently open as a blank new-entry form.
            platformLogE("EditCipher", "load failed for $id", e)
            loadError = e.message ?: "load failed"
        }
    }

    /** Persist: addCipher if new, updateCipher if editing. Returns the cipher id. */
    suspend fun save(vault: MobileVault): Result<String> {
        if (_form.value.typeTag == "login") maybeFetchFavicon(vault)
        val f = _form.value
        val payload = buildPayload(f, existingId, originalData)
        return runCatching {
            if (existingId != null) {
                repo.updateCipher(vault, payload)
                existingId!!
            } else {
                repo.addCipher(vault, payload)
            }
        }
    }

    /** Desktop maybeFetchFavicon parity: on login save, when the opt-in
     * fetch_favicons setting is on, fetch a favicon for the first URI and
     * stage it (or clear a stale one when the URI is gone). When the setting
     * is off this is a no-op and the stored favicon is preserved untouched. */
    private suspend fun maybeFetchFavicon(vault: MobileVault) {
        val f = _form.value
        val faviconsEnabled = repo.getSettings(vault)
            ?.let { json ->
                runCatching { (Json.parseToJsonElement(json) as? JsonObject).str("fetch_favicons") == "true" }
                    .getOrDefault(false)
            } == true
        if (!faviconsEnabled) return

        val domain = extractDomain(f.uris.firstOrNull { it.uri.isNotBlank() }?.uri)
        if (domain == null) {
            // No usable URI: clear any previously-stored favicon.
            if (f.faviconOverride != null || f.hasStoredFavicon) {
                _form.value = f.copy(faviconOverride = JsonNull)
            }
            return
        }
        val raw = runCatching { repo.fetchFavicon(vault, domain) }.getOrDefault("")
        val obj = raw.takeIf { it.isNotBlank() }
            ?.let { runCatching { Json.parseToJsonElement(it) as? JsonObject }.getOrNull() }
        val data = obj?.str("data")
        val mime = obj?.str("mime")
        _form.value = if (data != null && mime != null) {
            val icon = buildJsonObject { put("data", data); put("mime", mime) }
            _form.value.copy(faviconOverride = icon)
        } else {
            _form.value.copy(faviconOverride = JsonNull)
        }
    }

    /**
     * Daemon-wire JSON: {name, favorite, reprompt, notes, folder_id, tags,
     * custom_fields, kind: {type, data}}. `data` starts from the original
     * object (preserving unmodeled fields) and overlays the form values; a
     * cleared field sends null so the stored value is removed. New entries
     * start from an empty object (nulls).
     */
    internal fun buildPayload(f: EditForm, id: String?, originalData: JsonObject?): String {
        val data = buildJsonObject {
            originalData?.forEach { (k, v) -> put(k, v) }
            fieldsFor(f.typeTag).forEach { spec ->
                val v = f.values[spec.wireKey].orEmpty()
                put(spec.wireKey, if (v.isBlank()) JsonNull else JsonPrimitive(v))
            }
            if (f.typeTag == "login") {
                put("uris", JsonArray(f.uris
                    .filter { it.uri.isNotBlank() }
                    .map { u -> buildJsonObject {
                        put("uri", u.uri.trim())
                        u.matchStrategy?.let { put("match_strategy", it) }
                    } }))
                put("totp_uri", if (f.totpUri.isBlank()) JsonNull else JsonPrimitive(f.totpUri.trim()))
                // Fetched-on-save favicon; null override = untouched (the
                // originalData copy preserves whatever was stored).
                f.faviconOverride?.let { put("favicon", it) }
            }
        }
        val root = buildJsonObject {
            if (id != null) put("id", id)
            put("name", f.name)
            put("favorite", f.favorite)
            put("reprompt", f.reprompt)
            put("notes", if (f.notes.isBlank()) JsonNull else JsonPrimitive(f.notes))
            put("folder_id", f.folderId?.let { JsonPrimitive(it) } ?: JsonNull)
            put("tags", JsonArray(f.tags.map { JsonPrimitive(it) }))
            put("custom_fields", JsonArray(f.customFields
                .filter { it.name.isNotBlank() }
                .map { cf -> buildJsonObject {
                    put("name", cf.name.trim())
                    put("value", cf.value)
                    put("field_type", cf.linkedTarget
                        ?.let { target -> buildJsonObject { put("Linked", target) } }
                        ?: JsonPrimitive(cf.fieldType))
                } }))
            put("kind", buildJsonObject {
                put("type", f.typeTag)
                put("data", data)
            })
        }
        return root.toString()
    }
}

/** One login URI: {uri, match_strategy} on the wire. */
data class UriRow(val uri: String = "", val matchStrategy: String? = null)

/** Editable custom field. Wire field_type: "Text"|"Hidden"|"Boolean" or
 * {"Linked":"<target>"} (linkedTarget non-null). */
data class CustomFieldEdit(
    val name: String = "",
    val value: String = "",
    val fieldType: String = "Text",
    val linkedTarget: String? = null,
) {
    val isLinked: Boolean get() = linkedTarget != null
    val isBoolean: Boolean get() = !isLinked && fieldType == "Boolean"
    val isHidden: Boolean get() = !isLinked && fieldType == "Hidden"
}

data class EditForm(
    val name: String = "",
    val typeTag: String = "login",
    val notes: String = "",
    val favorite: Boolean = false,
    val reprompt: Boolean = false,
    /** Dynamic field values by wire key (see [fieldsFor]). */
    val values: Map<String, String> = emptyMap(),
    /** Login URIs (kind.data.uris); empty for other types. */
    val uris: List<UriRow> = emptyList(),
    /** Login TOTP seed URI (kind.data.totp_uri). */
    val totpUri: String = "",
    /** Fetched-on-save favicon: null = untouched (preserve stored value);
    * JsonNull = clear; object = {data, mime} to store. Set only when the
    * fetch_favicons opt-in is enabled. */
    val faviconOverride: JsonElement? = null,
    /** Whether the stored cipher has a favicon (drives the clear-on-no-URI
    * path in [EditCipherViewModel.maybeFetchFavicon]). */
    val hasStoredFavicon: Boolean = false,
    val customFields: List<CustomFieldEdit> = emptyList(),
    val tags: List<String> = emptyList(),
    val folderId: String? = null,
)

/** Parse a decrypted get_cipher response into the edit form. Wire shape
 * (runtime cipher_to_json): name/favorite/reprompt/notes/folder_id/tags/
 * custom_fields flat at root; kind.data carries the per-type fields including
 * uris and totp_uri for logins. */
internal fun parseLoadedCipher(raw: String): EditForm {
    val obj = Json.parseToJsonElement(raw) as JsonObject
    val kind = obj["kind"] as? JsonObject
    val tag = (kind?.get("type") as? JsonPrimitive)?.content ?: "login"
    val data = kind?.get("data") as? JsonObject ?: JsonObject(emptyMap())

    val uris = if (tag == "login") {
        (data["uris"] as? JsonArray)?.mapNotNull { el ->
            val o = el as? JsonObject ?: return@mapNotNull null
            val uri = o.str("uri") ?: return@mapNotNull null
            UriRow(uri, o.str("match_strategy"))
        }.orEmpty()
    } else emptyList()

    val customFields = (obj["custom_fields"] as? JsonArray)?.mapNotNull { el ->
        val o = el as? JsonObject ?: return@mapNotNull null
        val name = o.str("name") ?: return@mapNotNull null
        val ft = o["field_type"]
        val linked = ((ft as? JsonObject)?.get("Linked") as? JsonPrimitive)
            ?.takeUnless { it is JsonNull }?.content
        val ftContent = (ft as? JsonPrimitive)?.takeUnless { it is JsonNull }?.content
        CustomFieldEdit(
            name = name,
            value = o.str("value").orEmpty(),
            fieldType = when {
                linked != null -> "Linked"
                !ftContent.isNullOrBlank() -> ftContent
                else -> "Text"
            },
            linkedTarget = linked,
        )
    }.orEmpty()

    return EditForm(
        name = obj.str("name").orEmpty(),
        typeTag = tag,
        notes = obj.str("notes").orEmpty(),
        favorite = (obj["favorite"] as? JsonPrimitive)?.content == "true",
        reprompt = (obj["reprompt"] as? JsonPrimitive)?.content == "true",
        values = fieldsFor(tag).mapNotNull { spec ->
            val v = data.str(spec.wireKey)
            if (v.isNullOrBlank()) null else spec.wireKey to v
        }.toMap(),
        uris = uris,
        totpUri = if (tag == "login") (data.str("totp_uri") ?: obj.str("totp")).orEmpty() else "",
        hasStoredFavicon = (data["favicon"] as? JsonObject)?.str("data") != null,
        customFields = customFields,
        tags = (obj["tags"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }.orEmpty(),
        folderId = obj.str("folder_id"),
    )
}

/** kind.data out of a decrypted cipher response (empty object when absent). */
private fun extractData(raw: String): JsonObject? {
    val obj = Json.parseToJsonElement(raw) as? JsonObject ?: return null
    return (obj["kind"] as? JsonObject)?.get("data") as? JsonObject ?: JsonObject(emptyMap())
}

/** Desktop extractDomain parity: strip protocol, www, path, port and query;
 * lowercase. Null when nothing usable remains. */
internal fun extractDomain(uri: String?): String? {
    var s = uri?.trim().orEmpty()
    if (s.isEmpty()) return null
    s = s.removePrefix("https://").removePrefix("http://")
        .removePrefix("www.")
        .split("/").first()
        .split(":").first()
        .split("?").first()
        .lowercase()
    return s.ifEmpty { null }
}
